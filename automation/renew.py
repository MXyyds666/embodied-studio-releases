"""Renew both signed public catalogs without changing any release identity.

Run on the Windows signing host. Private keys stay in CurrentUser/My; only
four allowlisted catalog blobs may be published. A durable pending transaction
allows readback before retrying an interrupted GitHub ref update.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "automation" / "lib"))

from embodied_studio.application.version_management import UpdateCatalog, UpdateConfiguration
from embodied_studio.infrastructure.update_client import UpdateHttpClient
from embodied_studio.infrastructure.update_security import verify_catalog_signature

REPOSITORY = "MXyyds666/embodied-studio-releases"
BRANCH = "main"
ACCOUNT = "MXyyds666"
PRODUCTS = {
    "main": ("EmbodiedStudio", "78DB81B8-4578-4A6F-B825-3E7404D9A2F6", "cloud/stable/"),
    "standalone": ("EmbodiedStudioStandalone", "668EE63C-F2FF-4D43-B792-4D269D10186B", "standalone/cloud/stable/"),
}
ALLOWED_PATHS = frozenset(prefix + suffix for _, _, prefix in PRODUCTS.values()
                          for suffix in ("catalog.json", "catalog.sig"))


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON field: {key}")
            result[key] = value
        return result
    if not raw or len(raw) > 2 * 1024 * 1024:
        raise ValueError("JSON input is empty or oversized")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)


def save(path: Path, value) -> None:
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def utc(value: str) -> datetime:
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("UTC offset is required")
    return stamp.astimezone(timezone.utc)


def configurations(policy: dict) -> dict[str, UpdateConfiguration]:
    if (policy["schema_version"] != 1 or policy["repository"] != REPOSITORY
            or policy["branch"] != BRANCH or policy["account"] != ACCOUNT
            or policy["valid_hours"] != 168 or policy["renew_before_hours"] != 96
            or set(policy["configurations"]) != set(PRODUCTS)):
        raise ValueError("renewal policy exceeds the approved two-product scope")
    result = {}
    for label, (product, app_id, prefix) in PRODUCTS.items():
        config = UpdateConfiguration.from_bytes(json.dumps(policy["configurations"][label]).encode())
        base = f"https://raw.githubusercontent.com/{REPOSITORY}/{BRANCH}/{prefix}"
        if (not config.enabled or config.product != product or config.app_id != app_id
                or config.executable != product + ".exe" or config.channel != "stable"
                or config.architecture != "x64" or config.catalog_url != base + "catalog.json"
                or config.catalog_signature_url != base + "catalog.sig"):
            raise ValueError(f"unexpected public configuration: {label}")
        result[label] = config
    return result


def inspect_catalog(raw, signature, config, now, floor=0, previous=None, verifier=verify_catalog_signature):
    # Publishing maintenance may renew an expired, correctly signed document.
    # The client still parses all public readbacks at the real current time.
    verifier(raw, signature, config.public_trust)
    document = strict_json(raw)
    generated = utc(document["generated_at"])
    if generated > now + timedelta(minutes=15):
        raise ValueError("signed generation time is in the future; check the host clock")
    catalog = UpdateCatalog.from_bytes(raw, configuration=config, now=generated,
                                       highest_seen_sequence=floor)
    if catalog.expires_at - catalog.generated_at > timedelta(hours=168):
        raise ValueError("signed catalog validity exceeds seven days")
    if previous and catalog.sequence == previous["sequence"] and digest(raw) != previous["sha256"]:
        raise ValueError("a trusted sequence was reused with different catalog bytes")
    return catalog, document


def renewed_payload(raw, config, now, floor=0, reserved=0):
    document = strict_json(raw)
    old = UpdateCatalog.from_bytes(raw, configuration=config, now=utc(document["generated_at"]),
                                  highest_seen_sequence=floor)
    generated = max(now.replace(microsecond=0), old.generated_at)
    sequence = max(old.sequence, reserved) + 1
    document.update(sequence=sequence,
                    generated_at=generated.isoformat().replace("+00:00", "Z"),
                    expires_at=(generated + timedelta(hours=168)).isoformat().replace("+00:00", "Z"))
    result = (json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    UpdateCatalog.from_bytes(result, configuration=config, now=now, highest_seen_sequence=sequence)
    # Every field except these three must survive, including withdrawn releases.
    before = strict_json(raw)
    for field in ("sequence", "generated_at", "expires_at"):
        before.pop(field)
    after = strict_json(result)
    for field in ("sequence", "generated_at", "expires_at"):
        after.pop(field)
    if before != after:
        raise ValueError("renewal changed release metadata")
    return result


class GitHub:
    def __init__(self, executable):
        self.executable = str(executable)

    def api(self, endpoint, method="GET", data=None):
        command = [self.executable, "api", endpoint, "--method", method]
        raw = None
        if data is not None:
            command += ["--input", "-"]
            raw = json.dumps(data).encode("utf-8")
        environment = dict(os.environ)
        environment.pop("ES_CATALOG_SIGNING_KEY_PEM", None)
        environment.pop("GH_DEBUG", None)
        result = subprocess.run(command, input=raw, capture_output=True, timeout=60, env=environment,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode:
            raise RuntimeError(f"GitHub {method} {endpoint}: {result.stderr.decode('utf-8', 'replace')[-1200:]}")
        return json.loads(result.stdout)

    def endpoint(self, suffix):
        return f"repos/{REPOSITORY}/{suffix}"

    def authorize(self):
        required = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF": "refs/heads/main"}
        if any(os.environ.get(key) != value for key, value in required.items()):
            raise ValueError("Cloud publishing is restricted to this repository on its main branch")
        if os.environ.get("GITHUB_EVENT_NAME") not in {"schedule", "workflow_dispatch"}:
            raise ValueError("Cloud signing is not allowed for pull requests or unreviewed events")
        if self.api(self.endpoint(""))["id"] != 1426508599:
            raise ValueError("Unexpected release repository identity")

    def head(self):
        return self.api(self.endpoint(f"git/ref/heads/{BRANCH}"))["object"]["sha"]

    def snapshot(self):
        head = self.head()
        tree = self.api(self.endpoint("git/commits/" + head))["tree"]["sha"]
        entries = self.api(self.endpoint("git/trees/" + tree + "?recursive=1"))
        if entries.get("truncated"):
            raise ValueError("repository tree was truncated")
        found = {row["path"]: row for row in entries["tree"] if row["path"] in ALLOWED_PATHS}
        if set(found) != ALLOWED_PATHS:
            raise ValueError("one of the signed catalog files is missing")
        files = {}
        for path, row in found.items():
            if row["type"] != "blob" or row["mode"] != "100644" or row["size"] > 524288:
                raise ValueError("catalog input is not a bounded regular file")
            blob = self.api(self.endpoint("git/blobs/" + row["sha"]))
            if blob["encoding"] != "base64":
                raise ValueError("unexpected Git blob encoding")
            raw = base64.b64decode(blob["content"])
            if len(raw) != row["size"] or hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != row["sha"]:
                raise ValueError("Git blob size or digest mismatch")
            files[path] = raw
        return {"head": head, "tree": tree, "files": files}

    def create_commit(self, parent, base_tree, files):
        if set(files) != ALLOWED_PATHS:
            raise ValueError("only the four catalog paths may be committed")
        elements = []
        for path, raw in files.items():
            blob = self.api(self.endpoint("git/blobs"), "POST",
                            {"encoding": "base64", "content": base64.b64encode(raw).decode("ascii")})
            if blob["sha"] != hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest():
                raise ValueError("created blob digest mismatch")
            elements.append(dict(path=path, mode="100644", type="blob", sha=blob["sha"]))
        tree = self.api(self.endpoint("git/trees"), "POST", {"base_tree": base_tree, "tree": elements})
        commit = self.api(self.endpoint("git/commits"), "POST", {
            "message": "chore(updates): renew signed main and standalone catalogs",
            "tree": tree["sha"], "parents": [parent]})["sha"]
        changes = self.api(self.endpoint(f"compare/{parent}...{commit}"))
        if (len(changes["commits"]) != 1 or
                {row["filename"] for row in changes["files"]} != ALLOWED_PATHS or
                any(row["status"] != "modified" for row in changes["files"])):
            raise ValueError("renewal commit changed files outside the four catalog paths")
        return commit

    def advance(self, parent, commit):
        if self.head() != parent:
            raise RuntimeError("remote branch changed; do not overwrite another publication")
        result = self.api(self.endpoint(f"git/refs/heads/{BRANCH}"), "PATCH", {"sha": commit, "force": False})
        if os.environ.get("ES_RENEWAL_FAULT") == "after_publish":
            raise RuntimeError("Intentional after-publication interruption for recovery acceptance")
        if result["object"]["sha"] != commit:
            raise RuntimeError("GitHub returned an unexpected ref; read back before retrying")

    def contains(self, commit, head):
        if commit == head:
            return True
        return self.api(self.endpoint(f"compare/{commit}...{head}"))["status"] in {"ahead", "identical"}


class Signer:
    def __init__(self, policy, state_dir):
        self.policy, self.state_dir = policy, state_dir
        self.secret = os.environ.pop("ES_CATALOG_SIGNING_KEY_PEM", "")
        if not self.secret:
            raise ValueError("The approved cloud signing Secret is missing")
        self.calls = 0

    def _run(self, raw, trust, preflight):
        with tempfile.TemporaryDirectory(prefix="sign-", dir=self.state_dir) as directory:
            folder = Path(directory)
            payload, public = folder / "catalog.json", folder / "public-trust.json"
            payload.write_bytes(raw)
            save(public, trust)
            command = ["pwsh", "-NoProfile", "-File", str(ROOT / "automation/sign_cloud_catalog.ps1"),
                       "-InputFile", str(payload), "-PublicTrustFile", str(public),
                       "-SignatureFile", str(folder / "catalog.sig")]
            if preflight:
                command.append("-PreflightOnly")
            environment = dict(os.environ, ES_CATALOG_SIGNING_KEY_PEM=self.secret)
            result = subprocess.run(command, capture_output=True, timeout=90, env=environment,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode:
                raise RuntimeError("Cloud P256 signing failed; inspect the protected workflow configuration")
            return None if preflight else (folder / "catalog.sig").read_bytes()

    def preflight(self, raw, trust):
        self._run(raw, trust, True)

    def sign(self, raw, trust):
        self.calls += 1
        return self._run(raw, trust, False)


def public_probe(config, raw, signature):
    expected = strict_json(raw)["sequence"]
    fetched = UpdateHttpClient(config, timeout_seconds=20, retry_attempts=2).fetch_catalog(highest_seen_sequence=expected)
    if fetched.payload != raw or fetched.signature != signature:
        raise RuntimeError("public CDN has not returned the exact committed catalog/signature pair")
    return {"sequence": fetched.catalog.sequence, "sha256": digest(raw),
            "signature_sha256": digest(signature), "expires_at": fetched.catalog.expires_at.isoformat(),
            "trusted_key_id": fetched.trusted_key_id}


class Renewal:
    def __init__(self, policy, state_dir, remote, signer, *, verifier=verify_catalog_signature,
                 probe=public_probe, now=None, probe_attempts=6, wait=time.sleep):
        self.policy, self.state_dir, self.remote, self.signer = policy, state_dir, remote, signer
        self.configs = configurations(policy)
        self.verifier, self.probe, self.wait = verifier, probe, wait
        self.now = now or datetime.now(timezone.utc)
        self.probe_attempts = probe_attempts
        self.state_path = state_dir / "state.json"
        self.state = strict_json(self.state_path.read_bytes()) if self.state_path.exists() else {"schema_version": 1, "highest": {}, "pending": None}
        if self.state.get("checked_at") and utc(self.state["checked_at"]) > self.now + timedelta(minutes=15):
            raise ValueError("clock moved backwards since the last renewal check")

    def checkpoint(self):
        save(self.state_path, self.state)

    def inspect(self, files):
        result = {}
        for label, (_, _, prefix) in PRODUCTS.items():
            previous = self.state["highest"].get(label)
            floor = max(self.policy["minimum_sequences"][label], previous["sequence"] if previous else 0)
            result[label] = inspect_catalog(files[prefix + "catalog.json"], files[prefix + "catalog.sig"],
                                            self.configs[label], self.now, floor, previous, self.verifier)[0]
        return result

    def verify_public(self, files):
        result = {}
        for label, (_, _, prefix) in PRODUCTS.items():
            for attempt in range(self.probe_attempts):
                try:
                    result[label] = self.probe(self.configs[label], files[prefix + "catalog.json"], files[prefix + "catalog.sig"])
                    break
                except Exception:
                    if attempt + 1 == self.probe_attempts:
                        raise
                    self.wait(10)
        return result

    def run(self, *, force=False):
        self.remote.authorize()
        snapshot = self.remote.snapshot()
        catalogs = self.inspect(snapshot["files"])
        pending = self.state["pending"]
        changed = pending is not None
        if pending:
            prepared = {name: base64.b64decode(raw, validate=True) for name, raw in pending["files"].items()}
            applied = pending["commit"] and self.remote.contains(pending["commit"], snapshot["head"])
            expired_draft = any(utc(strict_json(prepared[prefix + "catalog.json"])["expires_at"]) <= self.now
                                for _, _, prefix in PRODUCTS.values())
            due_applied = applied and any(c.expires_at - self.now <= timedelta(hours=96) for c in catalogs.values())
            if (expired_draft and snapshot["head"] == pending["parent"]) or due_applied:
                # After a long offline interval, reserve the old sequence even
                # if its ref update was never observed. Never reuse a sequence
                # with new bytes. Retain the complete abandoned transaction.
                with (self.state_dir / "recovered-transactions.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"at": self.now.isoformat(), "status": "replaced_after_offline_interval",
                                             "publication_observed": bool(applied), "pending": pending},
                                            ensure_ascii=False, separators=(",", ":")) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                reserved = self.state.setdefault("reserved_sequences", {})
                for label, (_, _, prefix) in PRODUCTS.items():
                    reserved[label] = max(reserved.get(label, 0), strict_json(prepared[prefix + "catalog.json"])["sequence"])
                self.state["pending"] = None
                self.checkpoint()
                return self.run(force=True)
        if pending is None:
            # Detect loss/expiry of the signing credential before renewal is due.
            self.signer.preflight(snapshot["files"]["cloud/stable/catalog.json"], self.policy["configurations"]["main"]["public_trust"])
            due = force or any(c.expires_at - self.now <= timedelta(hours=96) for c in catalogs.values())
            if due:
                pending = {"parent": snapshot["head"], "base_tree": snapshot["tree"],
                           "phase": "signing", "commit": None, "files": {}}
                for label, (_, _, prefix) in PRODUCTS.items():
                    payload = renewed_payload(snapshot["files"][prefix + "catalog.json"], self.configs[label], self.now,
                                              catalogs[label].sequence, self.state.get("reserved_sequences", {}).get(label, 0))
                    pending["files"][prefix + "catalog.json"] = base64.b64encode(payload).decode("ascii")
                self.state["pending"] = pending
                self.checkpoint()
                changed = True
        if pending:
            files = {name: base64.b64decode(raw, validate=True) for name, raw in pending["files"].items()}
            already_applied = pending["commit"] and self.remote.contains(pending["commit"], snapshot["head"])
            if already_applied:
                # A later legitimate release may also have advanced the branch.
                files = snapshot["files"]
                for _, _, prefix in PRODUCTS.values():
                    if strict_json(files[prefix + "catalog.json"])["sequence"] < strict_json(base64.b64decode(pending["files"][prefix + "catalog.json"]))["sequence"]:
                        raise ValueError("published branch regressed below the pending trusted sequence")
            else:
                if snapshot["head"] != pending["parent"]:
                    raise RuntimeError("another publication advanced the branch; retained renewal needs review")
                for label, (_, _, prefix) in PRODUCTS.items():
                    payload = files[prefix + "catalog.json"]
                    if prefix + "catalog.sig" not in files:
                        files[prefix + "catalog.sig"] = self.signer.sign(payload, self.policy["configurations"][label]["public_trust"])
                        pending["files"][prefix + "catalog.sig"] = base64.b64encode(files[prefix + "catalog.sig"]).decode("ascii")
                        self.checkpoint()
                self.inspect(files)
                # Never publish an expired prepared transaction after an outage.
                for label, (_, _, prefix) in PRODUCTS.items():
                    UpdateCatalog.from_bytes(files[prefix + "catalog.json"], configuration=self.configs[label], now=self.now)
                if not pending["commit"]:
                    pending["commit"] = self.remote.create_commit(pending["parent"], pending["base_tree"], files)
                    pending["phase"] = "commit_created"
                    self.checkpoint()
                pending["phase"] = "updating_ref"
                self.checkpoint()
                self.remote.advance(pending["parent"], pending["commit"])
                snapshot = self.remote.snapshot()
                if not self.remote.contains(pending["commit"], snapshot["head"]):
                    raise RuntimeError("renewal commit is absent from the public branch after publication")
                files = snapshot["files"]
            self.inspect(files)
            pending["phase"] = "published_awaiting_public_readback"
            self.checkpoint()
        else:
            files = snapshot["files"]
        records = self.verify_public(files)
        result = {"status": "renewed" if changed else "unchanged", "checked_at": self.now.isoformat(),
                  "repository": REPOSITORY, "branch": BRANCH, "commit": snapshot["head"], "products": records,
                  "source_push": False, "installer_changes": False}
        if changed:
            result["renewal_commit"] = pending["commit"]
            with (self.state_dir / "renewals.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        self.state.update(highest={label: {"sequence": row["sequence"], "sha256": row["sha256"]}
                                   for label, row in records.items()}, pending=None, checked_at=self.now.isoformat(),
                          last_result=result, failure=None)
        self.checkpoint()
        return result

    def failure(self, error):
        message = f"{type(error).__name__}: {error}"
        old = self.state.get("failure") or {}
        failure = {"error": message, "last_seen": self.now.isoformat(),
                   "first_seen": old.get("first_seen", self.now.isoformat()) if old.get("error") == message else self.now.isoformat(),
                   "occurrences": old.get("occurrences", 0) + 1 if old.get("error") == message else 1}
        if old.get("error") != message:
            with (self.state_dir / "failures.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(failure, ensure_ascii=False) + "\n")
        self.state["failure"] = failure
        self.checkpoint()
        return {"status": "failed", **failure, "pending_preserved": bool(self.state["pending"])}


@contextmanager
def exclusive_lock(path):
    import msvcrt
    with path.open("a+b") as stream:
        stream.seek(0)
        if not stream.read(1):
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def prepare_publication(job, publication):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", publication):
        raise ValueError("publication must name a reviewed immutable input directory")
    if job.state["pending"]:
        return
    folder = ROOT / "automation" / "publications" / publication
    authorization = strict_json((folder / "publication.json").read_bytes())
    if authorization["repository"] != REPOSITORY or set(authorization["products"]) != set(PRODUCTS):
        raise ValueError("publication authorization has the wrong scope")
    job.remote.authorize()
    snapshot = job.remote.snapshot()
    current = job.inspect(snapshot["files"])
    prepared, already_present = {}, []
    for label, (_, _, prefix) in PRODUCTS.items():
        raw, signature = (folder / label / "catalog.json").read_bytes(), (folder / label / "catalog.sig").read_bytes()
        key = verify_catalog_signature(raw, signature, job.configs[label].public_trust)
        if key != "embodied-studio-catalog-20261020":
            raise ValueError("release changes require the retained offline project signing authority")
        source, document = inspect_catalog(raw, signature, job.configs[label], job.now,
                                           verifier=job.verifier)
        UpdateCatalog.from_bytes(raw, configuration=job.configs[label], now=job.now)
        baseline = strict_json(snapshot["files"][prefix + "catalog.json"])
        matching = document["releases"] == baseline["releases"] and document["download_hosts"] == baseline["download_hosts"]
        already_present.append(matching and current[label].sequence >= source.sequence)
        expected = authorization["products"][label]
        if expected["catalog_sha256"] != digest(raw):
            raise ValueError("publication source digest changed")
        if not matching or current[label].sequence < source.sequence:
            if digest(snapshot["files"][prefix + "catalog.json"]) != expected["expected_previous_catalog_sha256"]:
                raise ValueError("cloud catalog changed after publication review; rebase and re-sign inputs")
            if source.sequence <= current[label].sequence:
                raise ValueError("publication must use a new directory sequence")
        prepared[prefix + "catalog.json"] = base64.b64encode(raw).decode("ascii")
    if all(already_present):
        return
    if any(already_present):
        raise ValueError("publication is only partially present; retain evidence and review")
    job.state["pending"] = dict(parent=snapshot["head"], base_tree=snapshot["tree"], phase="signing",
                                 commit=None, files=prepared, publication=publication)
    job.checkpoint()


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--mode", choices=("renew", "validate", "publish"), default="renew")
    parser.add_argument("--publication", default="")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--state-directory", type=Path, required=True)
    arguments = parser.parse_args()
    policy = strict_json((ROOT / "automation/catalog_renewal.json").read_bytes())
    configurations(policy)
    directory = arguments.state_directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    with exclusive_lock(directory / "renewal.lock"):
        job = None
        try:
            signer = Signer(policy, directory)
            job = Renewal(policy, directory, GitHub(policy["github_cli"]), signer)
            if arguments.mode == "validate":
                job.remote.authorize()
                snapshot = job.remote.snapshot()
                job.inspect(snapshot["files"])
                challenge = b"EmbodiedStudio hosted catalog signing acceptance"
                proof = signer.sign(challenge, policy["configurations"]["main"]["public_trust"])
                key = verify_catalog_signature(challenge, proof, job.configs["main"].public_trust)
                if key != "embodied-studio-cloud-catalog-20261029":
                    raise ValueError("cloud signing key did not match the migration public key")
                result = dict(status="validated", public=job.verify_public(snapshot["files"]), key_id=key,
                              cloud_hosted=True, ref_updated=False)
            else:
                if arguments.mode == "publish":
                    prepare_publication(job, arguments.publication)
                result = job.run(force=arguments.force)
                result.update(cloud_hosted=True, operation=arguments.mode, signatures_generated=signer.calls)
            save(directory / "result.json", result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
            return 0
        except Exception as error:
            result = job.failure(error) if job else dict(status="failed", error=str(error), pending_preserved=False)
            save(directory / "result.json", result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
            return 1


if __name__ == "__main__":
    raise SystemExit(main())


