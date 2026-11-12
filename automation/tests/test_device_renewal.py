"""Offline device-channel scope, replay, and interruption tests."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_renewal as fixtures

renewal, NOW = fixtures.renewal, fixtures.NOW
ROOT = Path(__file__).resolve().parents[2]


class DeviceCatalogRenewalTests(unittest.TestCase):
    def setUp(self):
        renewal.select_profile("device")
        self.addCleanup(renewal.select_profile, "legacy")
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.directory = Path(self.folder.name)
        self.policy = json.loads((ROOT / "automation/device_catalog_renewal.json").read_text(encoding="utf-8"))
        self.remote = fixtures.Remote(fixtures.fixtures(self.policy))
        self.signer = fixtures.Signer()

    def probe(self, config, raw, signature):
        fixtures.fixture_verifier(raw, signature, config.public_trust)
        parsed = fixtures.UpdateCatalog.from_bytes(raw, configuration=config, now=NOW)
        return {"sequence": parsed.sequence, "sha256": renewal.digest(raw),
                "signature_sha256": renewal.digest(signature), "expires_at": parsed.expires_at.isoformat(),
                "trusted_key_id": "offline-fixture"}

    def job(self):
        return renewal.Renewal(self.policy, self.directory, self.remote, self.signer,
                               verifier=fixtures.fixture_verifier, probe=self.probe, now=NOW,
                               probe_attempts=1, wait=lambda _: self.fail("offline test must not wait"))

    def test_device_profile_isolated_and_due_renewal_changes_only_its_two_files(self):
        self.assertEqual(renewal.BRANCH, "device-catalog")
        self.assertEqual(renewal.ALLOWED_PATHS, {"stable/catalog.json", "stable/catalog.sig"})
        before = copy.deepcopy(self.remote.files)
        result = self.job().run()
        self.assertEqual(result["status"], "renewed")
        self.assertEqual((self.remote.created, self.remote.advances, self.signer.calls), (1, 1, 1))
        self.assertEqual(set(self.remote.files), renewal.ALLOWED_PATHS)
        old = json.loads(before["stable/catalog.json"])
        new = json.loads(self.remote.files["stable/catalog.json"])
        self.assertEqual(new["sequence"], old["sequence"] + 1)
        self.assertEqual(new["releases"], old["releases"])
        self.assertEqual(new["download_hosts"], old["download_hosts"])
        self.assertFalse(result["source_push"])
        self.assertFalse(result["installer_changes"])

    def test_old_identity_or_redirected_policy_is_rejected(self):
        for name, value in (("product", "EmbodiedStudio"),
                            ("app_id", "668EE63C-F2FF-4D43-B792-4D269D10186B"),
                            ("catalog_url", "https://raw.githubusercontent.com/MXyyds666/embodied-studio-releases/main/cloud/stable/catalog.json")):
            policy = copy.deepcopy(self.policy)
            policy["configurations"]["device"][name] = value
            with self.subTest(field=name), self.assertRaises(ValueError):
                renewal.configurations(policy)
        policy = copy.deepcopy(self.policy)
        policy["branch"] = "main"
        with self.assertRaises(ValueError):
            renewal.configurations(policy)
        raw = json.loads(self.remote.files["stable/catalog.json"])
        raw.update(product="EmbodiedStudio", app_id="78DB81B8-4578-4A6F-B825-3E7404D9A2F6")
        payload = json.dumps(raw).encode()
        self.remote.files["stable/catalog.json"] = payload
        self.remote.files["stable/catalog.sig"] = fixtures.fixture_signature(payload)
        with self.assertRaisesRegex(ValueError, "identity"):
            self.job().run()

    def test_uncertain_ref_update_is_recovered_without_republication(self):
        self.remote.fail_after = True
        job = self.job()
        with self.assertRaises(TimeoutError):
            job.run()
        self.assertEqual((self.remote.created, self.remote.advances, self.signer.calls), (1, 1, 1))
        result = self.job().run()
        self.assertEqual(result["status"], "renewed")
        self.assertEqual((self.remote.created, self.remote.advances, self.signer.calls), (1, 1, 1))
        self.assertIsNone(json.loads((self.directory / "state.json").read_text())["pending"])

    def test_extra_old_product_paths_are_rejected_before_api_write(self):
        remote = renewal.GitHub("unused")
        calls = []
        remote.api = lambda *args, **kwargs: calls.append(args)
        with self.assertRaisesRegex(ValueError, "device catalog"):
            remote.create_commit("parent", "tree", {**self.remote.files, "cloud/stable/catalog.json": b"old"})
        self.assertEqual(calls, [])

    def test_reviewed_device_publication_checks_previous_digest_and_updates_only_device(self):
        folder = self.directory / "automation/publications/device-release"
        (folder / "device").mkdir(parents=True)
        previous = self.remote.files["stable/catalog.json"]
        document = json.loads(previous)
        document["sequence"] += 1
        document["releases"][0]["release_notes"] = "Reviewed device release"
        raw = json.dumps(document).encode()
        (folder / "device/catalog.json").write_bytes(raw)
        (folder / "device/catalog.sig").write_bytes(fixtures.fixture_signature(raw))
        authorization = {"repository": renewal.REPOSITORY, "products": {"device": {
            "catalog_sha256": renewal.digest(raw),
            "expected_previous_catalog_sha256": renewal.digest(previous),
        }}}
        (folder / "publication.json").write_text(json.dumps(authorization), encoding="utf-8")
        def offline_verify(payload, signature, trust):
            fixtures.fixture_verifier(payload, signature, trust)
            return "embodied-studio-catalog-20261020"
        with patch.object(renewal, "ROOT", self.directory), \
             patch.object(renewal, "verify_catalog_signature", side_effect=offline_verify):
            job = self.job()
            renewal.prepare_publication(job, "device-release")
            self.assertEqual(job.state["pending"]["publication"], "device-release")
            result = job.run()
        self.assertEqual(result["status"], "renewed")
        self.assertEqual(set(self.remote.files), renewal.ALLOWED_PATHS)
        self.assertEqual(json.loads(self.remote.files["stable/catalog.json"])["releases"], document["releases"])
        self.assertEqual((self.remote.created, self.remote.advances), (1, 1))

    def test_device_publication_refuses_a_stale_reviewed_baseline(self):
        folder = self.directory / "automation/publications/stale-release"
        (folder / "device").mkdir(parents=True)
        document = json.loads(self.remote.files["stable/catalog.json"])
        document["sequence"] += 1
        document["releases"][0]["release_notes"] = "Changed"
        raw = json.dumps(document).encode()
        (folder / "device/catalog.json").write_bytes(raw)
        (folder / "device/catalog.sig").write_bytes(fixtures.fixture_signature(raw))
        authorization = {"repository": renewal.REPOSITORY, "products": {"device": {
            "catalog_sha256": renewal.digest(raw), "expected_previous_catalog_sha256": "0" * 64,
        }}}
        (folder / "publication.json").write_text(json.dumps(authorization), encoding="utf-8")
        with patch.object(renewal, "ROOT", self.directory), \
             patch.object(renewal, "verify_catalog_signature", return_value="embodied-studio-catalog-20261020"):
            with self.assertRaisesRegex(ValueError, "changed after publication review"):
                renewal.prepare_publication(self.job(), "stale-release")
        self.assertEqual((self.remote.created, self.remote.advances, self.signer.calls), (0, 0, 0))

    def test_workflow_is_scoped_and_requires_a_deliberate_enable_variable(self):
        text = (ROOT / ".github/workflows/renew-device-catalog.yml").read_text(encoding="utf-8")
        self.assertIn("ES_DEVICE_CATALOG_RENEWAL_ENABLED == 'true'", text)
        self.assertIn("'--profile', 'device'", text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertNotIn("pull_request:", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("cancel-in-progress: false", text)

    def test_legacy_profile_is_still_exactly_the_existing_two_products(self):
        renewal.select_profile("legacy")
        self.assertEqual(renewal.BRANCH, "main")
        self.assertEqual(set(renewal.PRODUCTS), {"main", "standalone"})
        self.assertEqual(renewal.ALLOWED_PATHS, {
            "cloud/stable/catalog.json", "cloud/stable/catalog.sig",
            "standalone/cloud/stable/catalog.json", "standalone/cloud/stable/catalog.sig",
        })
