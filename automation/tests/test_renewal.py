"""Offline renewal transaction tests; live P256/HTTPS acceptance is separate."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"automation/lib"))
from embodied_studio.application.version_management import UpdateCatalog

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("catalog_renewal", ROOT / "automation" / "renew.py")
renewal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renewal)
NOW = datetime(2026, 10, 29, 6, tzinfo=timezone.utc)


def fixture_signature(raw):
    return hashlib.sha256(raw).digest() * 2


def fixture_verifier(raw, signature, _trust):
    if signature != fixture_signature(raw):
        raise ValueError("fixture signature mismatch")


def fixtures(policy, generated=NOW - timedelta(days=4)):
    files = {}
    for label, (product, app_id, prefix) in renewal.PRODUCTS.items():
        entries = []
        for version, formal in (("0.2.0", True), ("0.1.0", False)):
            entries.append({
                "version": version, "windows_version": version + ".0", "build_id": "fixture-" + version,
                "runtime_directory": "app-" + version + "-fixture", "published_at": "2026-09-23T00:00:00Z",
                "release_notes": "Retain this exact entry", "formal_release": formal,
                "data_schema": 1, "compatible_data_schema_min": 1, "compatible_data_schema_max": 1,
                "min_updater_version": "0.1.0", "installer": {
                    "url": f"https://github.com/{renewal.REPOSITORY}/releases/download/fixture/{product}-{version}.exe",
                    "size": 10, "sha256": "ab" * 32, "publisher_certificate_sha256": None,
                    "launcher_sha256": "cd" * 32}})
        document = {"schema_version": 1, "product": product, "app_id": app_id,
                    "architecture": "x64", "channel": "stable", "sequence": policy["minimum_sequences"][label],
                    "generated_at": generated.isoformat(), "expires_at": (generated + timedelta(hours=168)).isoformat(),
                    "download_hosts": ["github.com", "release-assets.githubusercontent.com"], "releases": entries}
        raw = json.dumps(document).encode()
        files[prefix + "catalog.json"], files[prefix + "catalog.sig"] = raw, fixture_signature(raw)
    return files


class Remote:
    def __init__(self, files):
        self.files, self.current = copy.deepcopy(files), "original"
        self.parents, self.prepared = {"original": None}, {}
        self.created, self.advances = 0, 0
        self.fail_before, self.fail_after, self.conflict = False, False, False

    def authorize(self):
        return None

    def api(self, endpoint):
        assert endpoint == "user"
        return {"login": renewal.ACCOUNT}

    def snapshot(self):
        return {"head": self.current, "tree": "tree-" + self.current, "files": copy.deepcopy(self.files)}

    def create_commit(self, parent, base_tree, files):
        assert parent == self.current
        assert base_tree == "tree-" + parent
        assert set(files) == renewal.ALLOWED_PATHS
        self.created += 1
        name = "renewal-" + str(self.created)
        self.parents[name], self.prepared[name] = parent, copy.deepcopy(files)
        return name

    def contains(self, commit, head):
        while head is not None:
            if head == commit:
                return True
            head = self.parents[head]
        return False

    def advance(self, parent, commit):
        self.advances += 1
        if self.conflict:
            self.parents["concurrent"] = parent
            self.current = "concurrent"
        if self.current != parent:
            raise RuntimeError("remote branch changed")
        if self.fail_before:
            self.fail_before = False
            raise TimeoutError("ref response missing before mutation")
        self.current, self.files = commit, copy.deepcopy(self.prepared[commit])
        if self.fail_after:
            self.fail_after = False
            raise TimeoutError("ref response missing after mutation")


class Signer:
    def __init__(self):
        self.calls, self.preflights, self.fail_on = 0, 0, None
        self.missing_key = False

    def preflight(self, _raw, _trust):
        self.preflights += 1
        if self.missing_key:
            raise RuntimeError("private key unavailable")

    def sign(self, raw, _trust):
        self.calls += 1
        if self.calls == self.fail_on:
            raise RuntimeError("signing interrupted")
        return fixture_signature(raw)


class CatalogRenewalTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.directory = Path(self.folder.name)
        self.policy = json.loads((ROOT / "automation" / "catalog_renewal.json").read_text(encoding="utf-8"))
        self.remote, self.signer = Remote(fixtures(self.policy)), Signer()
        self.probe_failure = False

    def probe(self, config, raw, signature):
        if self.probe_failure:
            raise RuntimeError("CDN catalog/signature are from different cache generations")
        fixture_verifier(raw, signature, config.public_trust)
        catalog = UpdateCatalog.from_bytes(raw, configuration=config, now=self.clock)
        return {"sequence": catalog.sequence, "sha256": renewal.digest(raw),
                "signature_sha256": renewal.digest(signature), "expires_at": catalog.expires_at.isoformat(),
                "trusted_key_id": "offline-fixture-only"}

    def job(self, now=NOW):
        self.clock = now
        return renewal.Renewal(self.policy, self.directory, self.remote, self.signer,
                               verifier=fixture_verifier, probe=self.probe, now=now,
                               probe_attempts=1, wait=lambda _: self.fail("offline test must not wait"))

    def fail_run(self, job, message):
        with self.assertRaisesRegex(Exception, message) as caught:
            job.run()
        return job.failure(caught.exception)

    def test_due_renews_both_atomically_and_retains_all_release_fields(self):
        before = copy.deepcopy(self.remote.files)
        result = self.job().run()
        self.assertEqual(result["status"], "renewed")
        self.assertEqual((self.remote.created, self.remote.advances, self.signer.calls), (1, 1, 2))
        for label, (_, _, prefix) in renewal.PRODUCTS.items():
            old, new = json.loads(before[prefix + "catalog.json"]), json.loads(self.remote.files[prefix + "catalog.json"])
            self.assertEqual(new["sequence"], old["sequence"] + 1)
            self.assertEqual(renewal.utc(new["expires_at"]) - renewal.utc(new["generated_at"]), timedelta(hours=168))
            self.assertEqual(new["releases"], old["releases"])
            self.assertEqual(new["download_hosts"], old["download_hosts"])
        self.assertFalse(result["source_push"])
        self.assertFalse(result["installer_changes"])

    def test_fresh_catalogs_do_not_sign_or_commit(self):
        self.remote.files = fixtures(self.policy, NOW)
        self.assertEqual(self.job().run()["status"], "unchanged")
        self.assertEqual((self.remote.created, self.signer.calls, self.signer.preflights), (0, 0, 1))

    def test_one_due_catalog_renews_both(self):
        self.remote.files.update({key: value for key, value in fixtures(self.policy, NOW).items() if key.startswith("standalone/")})
        self.assertEqual(self.job().run()["status"], "renewed")
        self.assertEqual(self.signer.calls, 2)

    def test_expired_signed_catalog_can_be_renewed_but_client_rejects_expiry(self):
        self.remote.files = fixtures(self.policy, NOW - timedelta(days=9))
        config = renewal.configurations(self.policy)["main"]
        with self.assertRaisesRegex(ValueError, "expired"):
            UpdateCatalog.from_bytes(self.remote.files["cloud/stable/catalog.json"], configuration=config, now=NOW)
        self.assertEqual(self.job().run()["status"], "renewed")

    def test_tampered_or_invalid_signature_cannot_be_renewed(self):
        self.remote.files["cloud/stable/catalog.sig"] = b"X" * 64
        self.fail_run(self.job(), "signature mismatch")
        self.assertEqual((self.remote.created, self.signer.calls), (0, 0))

    def test_wrong_product_and_future_generation_fail_closed(self):
        for field, value, expected in (("product", "DifferentProduct", "identity"),
                                       ("generated_at", (NOW + timedelta(hours=1)).isoformat(), "future")):
            with self.subTest(field=field):
                self.remote.files = fixtures(self.policy)
                document = json.loads(self.remote.files["cloud/stable/catalog.json"])
                document[field] = value
                raw = json.dumps(document).encode()
                self.remote.files["cloud/stable/catalog.json"], self.remote.files["cloud/stable/catalog.sig"] = raw, fixture_signature(raw)
                self.fail_run(self.job(), expected)
        self.assertEqual(self.remote.created, 0)

    def test_longer_validity_is_rejected(self):
        document = json.loads(self.remote.files["cloud/stable/catalog.json"])
        document["expires_at"] = (NOW + timedelta(days=30)).isoformat()
        raw = json.dumps(document).encode()
        self.remote.files["cloud/stable/catalog.json"], self.remote.files["cloud/stable/catalog.sig"] = raw, fixture_signature(raw)
        self.fail_run(self.job(), "seven days")

    def test_sequence_downgrade_or_reuse_with_different_bytes_is_rejected(self):
        self.remote.files = fixtures(self.policy, NOW)
        self.job().run()
        original = copy.deepcopy(self.remote.files)
        for downgrade in (True, False):
            with self.subTest(downgrade=downgrade):
                self.remote.files = copy.deepcopy(original)
                document = json.loads(original["cloud/stable/catalog.json"])
                if downgrade:
                    document["sequence"] -= 1
                else:
                    document["releases"][0]["release_notes"] = "changed bytes with reused sequence"
                raw = json.dumps(document).encode()
                self.remote.files["cloud/stable/catalog.json"], self.remote.files["cloud/stable/catalog.sig"] = raw, fixture_signature(raw)
                self.fail_run(self.job(), "older|reused")
        self.assertEqual(self.remote.created, 0)

    def test_missing_key_reports_before_expiry_without_changing_feed(self):
        self.remote.files = fixtures(self.policy, NOW)
        self.signer.missing_key = True
        failure = self.fail_run(self.job(), "private key unavailable")
        self.assertFalse(failure["pending_preserved"])
        self.assertEqual(self.remote.created, 0)

    def test_second_signer_failure_resumes_only_missing_signature(self):
        self.signer.fail_on = 2
        failure = self.fail_run(self.job(), "signing interrupted")
        self.assertTrue(failure["pending_preserved"])
        self.assertEqual(self.remote.created, 0)
        self.job().run()
        self.assertEqual((self.remote.created, self.signer.calls), (1, 3))

    def test_unknown_ref_write_applied_is_read_back_without_republication(self):
        self.remote.fail_after = True
        self.fail_run(self.job(), "after mutation")
        self.job().run()
        self.assertEqual((self.remote.created, self.remote.advances, self.signer.calls), (1, 1, 2))

    def test_unknown_ref_write_not_applied_retries_the_same_commit(self):
        self.remote.fail_before = True
        self.fail_run(self.job(), "before mutation")
        self.job().run()
        self.assertEqual((self.remote.created, self.remote.advances, self.signer.calls), (1, 2, 2))

    def test_public_cache_mismatch_resumes_readback_without_resigning(self):
        self.probe_failure = True
        self.fail_run(self.job(), "cache generations")
        self.probe_failure = False
        self.job().run()
        self.assertEqual((self.remote.created, self.remote.advances, self.signer.calls), (1, 1, 2))

    def test_concurrent_publication_is_preserved_and_not_overwritten(self):
        self.remote.conflict = True
        self.fail_run(self.job(), "branch changed")
        self.assertEqual(self.remote.current, "concurrent")
        self.fail_run(self.job(), "another publication")
        self.assertEqual((self.remote.created, self.signer.calls), (1, 2))

    def test_expired_unpublished_transaction_reserves_sequence_before_recovery(self):
        self.remote.fail_before = True
        self.fail_run(self.job(), "before mutation")
        self.job(NOW + timedelta(days=9)).run()
        self.assertEqual((self.remote.created, self.signer.calls), (2, 4))
        self.assertEqual(json.loads(self.remote.files["cloud/stable/catalog.json"])["sequence"], 10)
        self.assertTrue((self.directory / "recovered-transactions.jsonl").exists())

    def test_applied_transaction_recovers_after_long_offline_interval(self):
        self.remote.fail_after = True
        self.fail_run(self.job(), "after mutation")
        self.job(NOW + timedelta(days=9)).run()
        self.assertEqual(json.loads(self.remote.files["cloud/stable/catalog.json"])["sequence"], 10)
        self.assertEqual(self.remote.created, 2)

    def test_clock_rollback_preserves_highest_sequence(self):
        self.remote.files = fixtures(self.policy, NOW)
        self.job().run()
        with self.assertRaisesRegex(ValueError, "clock moved backwards"):
            self.job(NOW - timedelta(hours=1))

    def test_policy_cannot_redirect_to_another_repository_or_feed(self):
        for key, value in (("repository", "someone/else"), ("branch", "other"), ("valid_hours", 720)):
            policy = copy.deepcopy(self.policy)
            policy[key] = value
            with self.assertRaisesRegex(ValueError, "approved"):
                renewal.configurations(policy)
        policy = copy.deepcopy(self.policy)
        policy["configurations"]["standalone"]["catalog_url"] = policy["configurations"]["main"]["catalog_url"]
        with self.assertRaisesRegex(ValueError, "unexpected public configuration"):
            renewal.configurations(policy)

    def test_duplicate_json_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            renewal.strict_json(b'{"sequence":1,"sequence":2}')

    def test_exclusive_writer_lock(self):
        with renewal.exclusive_lock(self.directory / "writer.lock"):
            with self.assertRaises(OSError):
                with renewal.exclusive_lock(self.directory / "writer.lock"):
                    self.fail("a second writer acquired the lock")

    def test_github_rejects_files_outside_allowlist_before_any_api_mutation(self):
        remote = renewal.GitHub("unused")
        with self.assertRaisesRegex(ValueError, "four catalog"):
            remote.create_commit("parent", "tree", {"README.md": b"changed"})


if __name__ == "__main__":
    unittest.main()
