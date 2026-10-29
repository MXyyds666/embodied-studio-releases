from pathlib import Path
import json
import os
import subprocess
import unittest
from unittest.mock import patch

import test_renewal as fixtures

renewal, NOW = fixtures.renewal, fixtures.NOW


class CloudBoundaryTests(unittest.TestCase):
    def test_cloud_publisher_requires_the_reviewed_repository_ref_and_event(self):
        valid = dict(GITHUB_ACTIONS="true", GITHUB_REPOSITORY=renewal.REPOSITORY,
                     GITHUB_REF="refs/heads/main", GITHUB_EVENT_NAME="schedule")
        for field, value in (("GITHUB_ACTIONS", "false"), ("GITHUB_REPOSITORY", "other/fork"),
                             ("GITHUB_REF", "refs/pull/1/merge"), ("GITHUB_EVENT_NAME", "pull_request_target")):
            remote = renewal.GitHub("unused")
            calls = []
            remote.api = lambda endpoint: calls.append(endpoint)
            with self.subTest(field=field), patch.dict(os.environ, {**valid, field: value}, clear=True):
                with self.assertRaisesRegex(ValueError, "restricted|not allowed"):
                    remote.authorize()
            self.assertEqual(calls, [])
        remote = renewal.GitHub("unused")
        remote.api = lambda endpoint: {"id": 1426508599}
        with patch.dict(os.environ, valid, clear=True):
            remote.authorize()

    def test_repository_name_is_also_bound_to_its_numeric_identity(self):
        remote = renewal.GitHub("unused")
        self.assertEqual(remote.endpoint(""), "repos/" + renewal.REPOSITORY)
        remote.api = lambda endpoint: {"id": 1}
        with patch.dict(os.environ, dict(GITHUB_ACTIONS="true", GITHUB_REPOSITORY=renewal.REPOSITORY,
                                        GITHUB_REF="refs/heads/main", GITHUB_EVENT_NAME="workflow_dispatch"), clear=True):
            with self.assertRaisesRegex(ValueError, "repository identity"):
                remote.authorize()

    def test_ref_update_is_non_forced_and_after_publish_fault_is_explicit(self):
        remote, calls = renewal.GitHub("unused"), []
        remote.head = lambda: "parent"
        def api(endpoint, method, data):
            calls.append((endpoint, method, data))
            return {"object": {"sha": "commit"}}
        remote.api = api
        with patch.dict(os.environ, {"ES_RENEWAL_FAULT": "after_publish"}):
            with self.assertRaisesRegex(RuntimeError, "Intentional after-publication"):
                remote.advance("parent", "commit")
        self.assertEqual(calls[0][2], {"sha": "commit", "force": False})
        self.assertEqual(calls[0][1], "PATCH")

    def test_workflow_uses_hosted_runners_and_does_not_grant_pull_requests_secrets(self):
        source = (renewal.ROOT / ".github/workflows/renew-update-catalogs.yml").read_text()
        self.assertIn("runs-on: windows-2022", source)
        self.assertNotIn("self-hosted", source)
        self.assertNotIn("pull_request:", source)
        self.assertIn("cancel-in-progress: false", source)
        self.assertIn("persist-credentials: false", source)
        self.assertIn("cron: '17 1,13 * * *'", source)
        self.assertIn("retention-days: 14", source)

    def test_dotnet_signer_import_signature_and_wrong_public_key(self):
        script = renewal.ROOT / "automation/tests/verify_signer.ps1"
        result = subprocess.run(["pwsh", "-NoProfile", "-File", str(script), "-Signer",
                                 str(renewal.ROOT / "automation/sign_cloud_catalog.ps1")],
                                capture_output=True, timeout=90,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode("utf-8", "replace"))
        self.assertIn(b'"status":"passed"', result.stdout)


class PublicationTests(fixtures.CatalogRenewalTests):
    def inputs(self):
        self.publication_root = self.directory / "repo"
        folder = self.publication_root / "automation/publications/fixture"
        products = {}
        for label, (_, _, prefix) in renewal.PRODUCTS.items():
            target = folder / label
            target.mkdir(parents=True)
            original = self.remote.files[prefix + "catalog.json"]
            document = json.loads(renewal.renewed_payload(original, self.job().configs[label], NOW))
            document["releases"][0]["release_notes"] = "Approved migration release note"
            raw = json.dumps(document).encode()
            (target / "catalog.json").write_bytes(raw)
            (target / "catalog.sig").write_bytes(fixtures.fixture_signature(raw))
            products[label] = dict(catalog_sha256=renewal.digest(raw), expected_previous_catalog_sha256=renewal.digest(original))
        (folder / "publication.json").write_text(json.dumps(dict(repository=renewal.REPOSITORY, products=products)))
        return folder

    def test_signed_publication_can_change_entries_and_replay_is_a_noop(self):
        self.inputs()
        job = self.job()
        with patch.object(renewal, "ROOT", self.publication_root), patch.object(renewal, "verify_catalog_signature", return_value="embodied-studio-catalog-20261020"):
            renewal.prepare_publication(job, "fixture")
            self.assertEqual(job.run()["status"], "renewed")
            resumed = self.job()
            renewal.prepare_publication(resumed, "fixture")
            self.assertEqual(resumed.run()["status"], "unchanged")
        self.assertEqual((self.remote.created, self.signer.calls), (1, 2))
        self.assertEqual(json.loads(self.remote.files["cloud/stable/catalog.json"])["releases"][0]["release_notes"], "Approved migration release note")

    def test_cloud_key_cannot_authorize_new_release_entries(self):
        self.inputs()
        with patch.object(renewal, "ROOT", self.publication_root), patch.object(renewal, "verify_catalog_signature", return_value="embodied-studio-cloud-catalog-20261029"):
            with self.assertRaisesRegex(ValueError, "offline project signing authority"):
                renewal.prepare_publication(self.job(), "fixture")
        self.assertEqual(self.remote.created, 0)

    def test_publication_base_must_match_reviewed_previous_catalog(self):
        folder = self.inputs()
        auth = json.loads((folder / "publication.json").read_bytes())
        auth["products"]["main"]["expected_previous_catalog_sha256"] = "ff" * 32
        (folder / "publication.json").write_text(json.dumps(auth))
        with patch.object(renewal, "ROOT", self.publication_root), patch.object(renewal, "verify_catalog_signature", return_value="embodied-studio-catalog-20261020"):
            with self.assertRaisesRegex(ValueError, "changed after publication review"):
                renewal.prepare_publication(self.job(), "fixture")


for _name in list(fixtures.CatalogRenewalTests.__dict__):
    if _name.startswith("test_"):
        setattr(PublicationTests, _name, None)
