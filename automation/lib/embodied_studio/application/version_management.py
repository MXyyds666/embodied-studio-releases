"""Host release identity and signed online-update catalog contracts.

This module is deliberately independent from Qt, networking, installers and
device transports.  A catalog is untrusted input until its detached signature
has been verified by the infrastructure layer *and* this parser accepts every
field.  Unknown or duplicated fields are rejected so a newer server contract
cannot silently acquire weaker semantics in an older client.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from functools import total_ordering
import json
from pathlib import Path
import re
from typing import Iterable
from urllib.parse import urlsplit


CATALOG_SCHEMA_VERSION = 1
UPDATE_CONFIGURATION_SCHEMA_VERSION = 1
BUILD_INFORMATION_SCHEMA_VERSION = 1
CURRENT_DATA_SCHEMA = 1
MAX_CATALOG_BYTES = 512 * 1024
MAX_INSTALLER_BYTES = 512 * 1024 * 1024
MAX_RELEASES = 64

_SEMVER = re.compile(
    r"^(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)\."
    r"(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_PUBLIC_BLOB = re.compile(r"^[0-9a-fA-F]{144}$")
_HOST = re.compile(
    r"^(?:localhost|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\."
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)$"
)


class UpdateContractError(ValueError):
    """Raised when release/update metadata violates the frozen contract."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise UpdateContractError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _strict_json(raw: bytes, *, maximum: int) -> object:
    if not raw or len(raw) > maximum:
        raise UpdateContractError("JSON document size is outside the accepted range")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise UpdateContractError("JSON document is not UTF-8") from error
    if text.startswith("\ufeff"):
        raise UpdateContractError("JSON document must not contain a BOM")
    try:
        return json.loads(text, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, TypeError) as error:
        raise UpdateContractError("invalid JSON document") from error


def _require_exact_fields(
    value: object,
    expected: set[str],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise UpdateContractError(f"{label} fields do not match schema")
    return value


def _require_text(value: object, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise UpdateContractError(f"{label} must be a canonical non-empty string")
    if len(value) > maximum or any(ord(character) < 32 for character in value):
        raise UpdateContractError(f"{label} is too long or contains control characters")
    return value


def _require_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise UpdateContractError(f"{label} must be a boolean")
    return value


def _require_int(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise UpdateContractError(f"{label} is outside the accepted range")
    return value


def _require_digest(value: object, label: str) -> str:
    text = _require_text(value, label, maximum=64)
    if not _HEX_64.fullmatch(text):
        raise UpdateContractError(f"{label} must be a SHA-256 digest")
    return text.lower()


def _parse_utc(value: object, label: str) -> datetime:
    text = _require_text(value, label, maximum=40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise UpdateContractError(f"{label} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise UpdateContractError(f"{label} must use UTC")
    return parsed.astimezone(timezone.utc)


def _validated_url(
    value: object,
    label: str,
    *,
    allow_test_http: bool = False,
) -> str:
    text = _require_text(value, label, maximum=2048)
    parts = urlsplit(text)
    allowed_scheme = parts.scheme == "https" or (
        allow_test_http and parts.scheme == "http"
    )
    if (
        not allowed_scheme
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or parts.query
        or not parts.path.startswith("/")
    ):
        raise UpdateContractError(f"{label} must be a credential-free canonical URL")
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise UpdateContractError(f"{label} uses an invalid port")
    hostname = parts.hostname.casefold()
    if not _HOST.fullmatch(hostname):
        # urlsplit returns bracketless IPv6.  Production endpoints deliberately
        # use DNS names; tests may use IPv4 loopback.
        if not allow_test_http or hostname not in {"127.0.0.1", "::1"}:
            raise UpdateContractError(f"{label} uses an unsupported host")
    return text


@total_ordering
@dataclass(frozen=True, slots=True)
class SemanticVersion:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: object, label: str = "version") -> "SemanticVersion":
        text = _require_text(value, label, maximum=96)
        match = _SEMVER.fullmatch(text)
        if match is None:
            raise UpdateContractError(f"{label} is not valid SemVer")
        prerelease = tuple(match.group(4).split(".")) if match.group(4) else ()
        build = tuple(match.group(5).split(".")) if match.group(5) else ()
        for identifier in prerelease:
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                raise UpdateContractError(f"{label} has a leading-zero prerelease identifier")
        return cls(
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            prerelease,
            build,
        )

    def __str__(self) -> str:
        value = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            value += "-" + ".".join(self.prerelease)
        if self.build:
            value += "+" + ".".join(self.build)
        return value

    def _precedence(self) -> tuple[int, int, int, tuple[tuple[int, object], ...]]:
        # A normal version has higher precedence than any prerelease.  Numeric
        # identifiers compare numerically and sort before non-numeric values.
        if not self.prerelease:
            pre: tuple[tuple[int, object], ...] = ((2, ""),)
        else:
            pre = tuple(
                (0, int(item)) if item.isdigit() else (1, item)
                for item in self.prerelease
            )
        return self.major, self.minor, self.patch, pre

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return NotImplemented
        base_self = (self.major, self.minor, self.patch)
        base_other = (other.major, other.minor, other.patch)
        if base_self != base_other:
            return base_self < base_other
        if not self.prerelease:
            # A normal version always sorts after a prerelease with the same
            # major/minor/patch tuple.
            return False
        if not other.prerelease:
            return True
        for left, right in zip(self.prerelease, other.prerelease):
            if left == right:
                continue
            left_numeric, right_numeric = left.isdigit(), right.isdigit()
            if left_numeric and right_numeric:
                return int(left) < int(right)
            if left_numeric != right_numeric:
                return left_numeric
            return left < right
        return len(self.prerelease) < len(other.prerelease)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            return False
        # Build metadata deliberately does not affect SemVer precedence.
        return (
            self.major,
            self.minor,
            self.patch,
            self.prerelease,
        ) == (
            other.major,
            other.minor,
            other.patch,
            other.prerelease,
        )

    def __hash__(self) -> int:
        # SemVer build metadata does not participate in precedence/equality,
        # so it must not participate in hashing either.
        return hash((self.major, self.minor, self.patch, self.prerelease))


@dataclass(frozen=True, slots=True)
class UpdateTrustKey:
    key_id: str
    public_blob: bytes


def _parse_trust(value: object, *, allow_empty: bool) -> tuple[UpdateTrustKey, ...]:
    trust = _require_exact_fields(value, {"schema_version", "keys"}, "public trust")
    if trust["schema_version"] != 1 or type(trust["schema_version"]) is not int:
        raise UpdateContractError("unsupported public trust schema")
    keys = trust["keys"]
    if not isinstance(keys, list) or len(keys) > 4 or (not keys and not allow_empty):
        raise UpdateContractError("public trust requires one to four keys")
    parsed: list[UpdateTrustKey] = []
    ids: set[str] = set()
    blobs: set[bytes] = set()
    for index, item in enumerate(keys):
        row = _require_exact_fields(item, {"id", "public_blob_hex"}, f"trust key {index}")
        key_id = _require_text(row["id"], f"trust key {index} id", maximum=96)
        if not _SAFE_ID.fullmatch(key_id):
            raise UpdateContractError("invalid public trust key id")
        blob_hex = _require_text(
            row["public_blob_hex"],
            f"trust key {index} blob",
            maximum=144,
        )
        if not _HEX_PUBLIC_BLOB.fullmatch(blob_hex):
            raise UpdateContractError("public trust key must be a 72-byte P256 blob")
        blob = bytes.fromhex(blob_hex)
        if blob[:8] != b"ECS1\x20\x00\x00\x00":
            raise UpdateContractError("only ECDSA P256 public blobs are accepted")
        if key_id in ids or blob in blobs:
            raise UpdateContractError("duplicate public trust key")
        ids.add(key_id)
        blobs.add(blob)
        parsed.append(UpdateTrustKey(key_id, blob))
    return tuple(parsed)


@dataclass(frozen=True, slots=True)
class UpdateConfiguration:
    enabled: bool
    product: str
    app_id: str
    executable: str
    architecture: str
    channel: str
    catalog_url: str | None
    catalog_signature_url: str | None
    automatic_check: bool
    check_interval_seconds: int
    catalog_max_bytes: int
    installer_max_bytes: int
    expected_publisher_sha256: str | None
    public_trust: tuple[UpdateTrustKey, ...]
    authenticode_required: bool = True

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        allow_test_http: bool = False,
    ) -> "UpdateConfiguration":
        value = _strict_json(raw, maximum=64 * 1024)
        # An absent policy preserves the original pinned-publisher contract.
        # Only the local packaged configuration can select project-only trust.
        authenticode_required = _require_bool(
            value.pop("authenticode_required", True) if isinstance(value, dict) else True,
            "authenticode_required",
        )
        document = _require_exact_fields(
            value,
            {
                "schema_version",
                "enabled",
                "product",
                "app_id",
                "executable",
                "architecture",
                "channel",
                "catalog_url",
                "catalog_signature_url",
                "automatic_check",
                "check_interval_seconds",
                "catalog_max_bytes",
                "installer_max_bytes",
                "expected_publisher_sha256",
                "public_trust",
            },
            "update configuration",
        )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != UPDATE_CONFIGURATION_SCHEMA_VERSION
        ):
            raise UpdateContractError("unsupported update configuration schema")
        enabled = _require_bool(document["enabled"], "enabled")
        product = _require_text(document["product"], "product", maximum=96)
        app_id = _require_text(document["app_id"], "app_id", maximum=64)
        executable = _require_text(
            document["executable"], "executable", maximum=96
        )
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,91}\.exe", executable, re.IGNORECASE)
            or Path(executable).name != executable
        ):
            raise UpdateContractError("invalid update executable name")
        architecture = _require_text(
            document["architecture"], "architecture", maximum=16
        )
        channel = _require_text(document["channel"], "channel", maximum=32)
        automatic = _require_bool(document["automatic_check"], "automatic_check")
        interval = _require_int(
            document["check_interval_seconds"],
            "check_interval_seconds",
            minimum=3600,
            maximum=7 * 24 * 3600,
        )
        catalog_limit = _require_int(
            document["catalog_max_bytes"],
            "catalog_max_bytes",
            minimum=1024,
            maximum=MAX_CATALOG_BYTES,
        )
        installer_limit = _require_int(
            document["installer_max_bytes"],
            "installer_max_bytes",
            minimum=1024 * 1024,
            maximum=MAX_INSTALLER_BYTES,
        )
        if enabled:
            catalog_url = _validated_url(
                document["catalog_url"],
                "catalog_url",
                allow_test_http=allow_test_http,
            )
            signature_url = _validated_url(
                document["catalog_signature_url"],
                "catalog_signature_url",
                allow_test_http=allow_test_http,
            )
            publisher_value = document["expected_publisher_sha256"]
            publisher = (
                None if publisher_value is None and not authenticode_required
                else _require_digest(publisher_value, "expected_publisher_sha256")
            )
            trust = _parse_trust(document["public_trust"], allow_empty=False)
        else:
            if document["catalog_url"] not in (None, ""):
                raise UpdateContractError("disabled update configuration must not retain a catalog URL")
            if document["catalog_signature_url"] not in (None, ""):
                raise UpdateContractError("disabled update configuration must not retain a signature URL")
            if document["expected_publisher_sha256"] not in (None, ""):
                raise UpdateContractError("disabled update configuration must not retain a publisher identity")
            catalog_url = signature_url = publisher = None
            trust = _parse_trust(document["public_trust"], allow_empty=True)
            if trust:
                raise UpdateContractError("disabled update configuration must not retain trust keys")
            if automatic:
                raise UpdateContractError("disabled update configuration cannot check automatically")
        return cls(
            enabled=enabled,
            product=product,
            app_id=app_id,
            executable=executable,
            architecture=architecture,
            channel=channel,
            catalog_url=catalog_url,
            catalog_signature_url=signature_url,
            automatic_check=automatic,
            check_interval_seconds=interval,
            catalog_max_bytes=catalog_limit,
            installer_max_bytes=installer_limit,
            expected_publisher_sha256=publisher,
            public_trust=trust,
            authenticode_required=authenticode_required,
        )

    @classmethod
    def from_path(
        cls,
        path: Path,
        *,
        allow_test_http: bool = False,
    ) -> "UpdateConfiguration":
        with path.open("rb") as stream:
            raw = stream.read(64 * 1024 + 1)
        return cls.from_bytes(raw, allow_test_http=allow_test_http)


@dataclass(frozen=True, slots=True)
class BuildInformation:
    build_id: str
    channel: str
    formal_release: bool
    git_commit: str | None
    source_fingerprint_sha256: str | None
    built_at: datetime | None
    data_schema: int

    @classmethod
    def from_bytes(cls, raw: bytes) -> "BuildInformation":
        document = _require_exact_fields(
            _strict_json(raw, maximum=16 * 1024),
            {
                "schema_version",
                "build_id",
                "channel",
                "formal_release",
                "git_commit",
                "source_fingerprint_sha256",
                "built_at",
                "data_schema",
            },
            "build information",
        )
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != BUILD_INFORMATION_SCHEMA_VERSION
        ):
            raise UpdateContractError("unsupported build information schema")
        build_id = _require_text(document["build_id"], "build_id", maximum=96)
        if not _SAFE_ID.fullmatch(build_id):
            raise UpdateContractError("invalid build_id")
        channel = _require_text(document["channel"], "channel", maximum=32)
        formal = _require_bool(document["formal_release"], "formal_release")
        commit_raw = document["git_commit"]
        if commit_raw is None:
            commit = None
        else:
            commit = _require_text(commit_raw, "git_commit", maximum=64).lower()
            if not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise UpdateContractError("git_commit must be a full SHA-1 object id")
        fingerprint_raw = document["source_fingerprint_sha256"]
        fingerprint = (
            None
            if fingerprint_raw is None
            else _require_digest(fingerprint_raw, "source_fingerprint_sha256")
        )
        built_at = (
            None
            if document["built_at"] is None
            else _parse_utc(document["built_at"], "built_at")
        )
        data_schema = _require_int(
            document["data_schema"], "data_schema", minimum=1, maximum=65535
        )
        if formal and (commit is None or fingerprint is None or built_at is None):
            raise UpdateContractError("formal build information requires complete provenance")
        return cls(
            build_id,
            channel,
            formal,
            commit,
            fingerprint,
            built_at,
            data_schema,
        )


@dataclass(frozen=True, slots=True)
class InstallerArtifact:
    url: str
    size: int
    sha256: str
    publisher_certificate_sha256: str | None
    launcher_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class ReleaseEntry:
    version: SemanticVersion
    version_text: str
    windows_version: str
    build_id: str
    runtime_directory: str
    published_at: datetime
    release_notes: str
    formal_release: bool
    data_schema: int
    compatible_data_schema_min: int
    compatible_data_schema_max: int
    min_updater_version: SemanticVersion
    installer: InstallerArtifact

    @property
    def identity(self) -> str:
        return f"{self.version_text}+{self.build_id}@{self.installer.sha256}"

    def can_read_data_schema(self, schema: int) -> bool:
        return self.compatible_data_schema_min <= schema <= self.compatible_data_schema_max


@dataclass(frozen=True, slots=True)
class UpdateCatalog:
    product: str
    app_id: str
    architecture: str
    channel: str
    sequence: int
    generated_at: datetime
    expires_at: datetime
    download_hosts: tuple[str, ...]
    releases: tuple[ReleaseEntry, ...]

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        configuration: UpdateConfiguration,
        now: datetime | None = None,
        highest_seen_sequence: int = 0,
        allow_test_http: bool = False,
    ) -> "UpdateCatalog":
        if not configuration.enabled:
            raise UpdateContractError("online updates are disabled")
        document = _require_exact_fields(
            _strict_json(raw, maximum=configuration.catalog_max_bytes),
            {
                "schema_version",
                "product",
                "app_id",
                "architecture",
                "channel",
                "sequence",
                "generated_at",
                "expires_at",
                "download_hosts",
                "releases",
            },
            "update catalog",
        )
        if type(document["schema_version"]) is not int or document["schema_version"] != CATALOG_SCHEMA_VERSION:
            raise UpdateContractError("unsupported update catalog schema")
        product = _require_text(document["product"], "catalog product", maximum=96)
        app_id = _require_text(document["app_id"], "catalog app_id", maximum=64)
        architecture = _require_text(document["architecture"], "catalog architecture", maximum=16)
        channel = _require_text(document["channel"], "catalog channel", maximum=32)
        if (
            product != configuration.product
            or app_id.casefold() != configuration.app_id.casefold()
            or architecture != configuration.architecture
            or channel != configuration.channel
        ):
            raise UpdateContractError("catalog identity does not match this application")
        sequence = _require_int(
            document["sequence"], "catalog sequence", minimum=1, maximum=2**63 - 1
        )
        if sequence < highest_seen_sequence:
            raise UpdateContractError("catalog sequence is older than the highest trusted catalog")
        generated_at = _parse_utc(document["generated_at"], "generated_at")
        expires_at = _parse_utc(document["expires_at"], "expires_at")
        clock = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if expires_at <= generated_at or expires_at <= clock:
            raise UpdateContractError("catalog is expired or has an invalid validity window")
        # A future-dated catalog beyond normal clock skew is rejected.  This is
        # a metadata trust boundary, not a device-operation timeout.
        if generated_at.timestamp() > clock.timestamp() + 15 * 60:
            raise UpdateContractError("catalog generation time is implausibly in the future")
        hosts_raw = document["download_hosts"]
        if not isinstance(hosts_raw, list) or not 1 <= len(hosts_raw) <= 8:
            raise UpdateContractError("catalog requires one to eight download hosts")
        hosts: list[str] = []
        for value in hosts_raw:
            host = _require_text(value, "download host", maximum=253).casefold()
            if not _HOST.fullmatch(host):
                if not allow_test_http or host not in {"127.0.0.1", "::1"}:
                    raise UpdateContractError("invalid download host")
            if host in hosts:
                raise UpdateContractError("duplicate download host")
            hosts.append(host)
        releases_raw = document["releases"]
        if not isinstance(releases_raw, list) or not 1 <= len(releases_raw) <= MAX_RELEASES:
            raise UpdateContractError("catalog requires a bounded release history")
        releases: list[ReleaseEntry] = []
        build_identities: set[tuple[str, str]] = set()
        runtime_directories: set[str] = set()
        for index, value in enumerate(releases_raw):
            entry = _parse_release(
                value,
                label=f"release {index}",
                installer_limit=configuration.installer_max_bytes,
                download_hosts=set(hosts),
                expected_publisher=configuration.expected_publisher_sha256,
                authenticode_required=configuration.authenticode_required,
                allow_test_http=allow_test_http,
            )
            build_identity = (entry.version_text, entry.build_id)
            if build_identity in build_identities:
                # The running application can identify itself by version and
                # build id, but not by the installer digest that produced it.
                # Allowing two packages for that identity would make the
                # mandatory rollback package ambiguous.
                raise UpdateContractError("duplicate release build identity")
            if entry.runtime_directory.casefold() in runtime_directories:
                raise UpdateContractError("duplicate release runtime directory")
            build_identities.add(build_identity)
            runtime_directories.add(entry.runtime_directory.casefold())
            releases.append(entry)
        ordered = sorted(
            releases,
            key=lambda item: (item.version, item.published_at, item.build_id),
            reverse=True,
        )
        if ordered != releases:
            raise UpdateContractError("catalog releases must be newest first")
        return cls(
            product,
            app_id,
            architecture,
            channel,
            sequence,
            generated_at,
            expires_at,
            tuple(hosts),
            tuple(releases),
        )

    def newest_update(
        self,
        *,
        current_version: SemanticVersion,
        current_data_schema: int,
        updater_version: SemanticVersion,
    ) -> ReleaseEntry | None:
        for release in self.releases:
            if (
                release.formal_release
                and release.version > current_version
                and updater_version >= release.min_updater_version
                and release.can_read_data_schema(current_data_schema)
            ):
                return release
        return None

    def rollback_candidates(
        self,
        *,
        current_version: SemanticVersion,
        current_data_schema: int,
        updater_version: SemanticVersion,
    ) -> tuple[ReleaseEntry, ...]:
        return tuple(
            release
            for release in self.releases
            if (
                release.formal_release
                and release.version < current_version
                and updater_version >= release.min_updater_version
                and release.can_read_data_schema(current_data_schema)
            )
        )


def _parse_release(
    value: object,
    *,
    label: str,
    installer_limit: int,
    download_hosts: set[str],
    expected_publisher: str | None,
    allow_test_http: bool,
    authenticode_required: bool = True,
) -> ReleaseEntry:
    row = _require_exact_fields(
        value,
        {
            "version",
            "windows_version",
            "build_id",
            "runtime_directory",
            "published_at",
            "release_notes",
            "formal_release",
            "data_schema",
            "compatible_data_schema_min",
            "compatible_data_schema_max",
            "min_updater_version",
            "installer",
        },
        label,
    )
    version_text = _require_text(row["version"], f"{label} version", maximum=96)
    version = SemanticVersion.parse(version_text, f"{label} version")
    windows_version = _require_text(
        row["windows_version"], f"{label} windows_version", maximum=32
    )
    if not re.fullmatch(r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){3}", windows_version):
        raise UpdateContractError(f"{label} has an invalid Windows version")
    if any(int(part) > 65535 for part in windows_version.split(".")):
        raise UpdateContractError(f"{label} Windows version exceeds PE limits")
    build_id = _require_text(row["build_id"], f"{label} build_id", maximum=96)
    if not _SAFE_ID.fullmatch(build_id):
        raise UpdateContractError(f"{label} has an invalid build_id")
    runtime_directory = _require_text(
        row["runtime_directory"], f"{label} runtime_directory", maximum=160
    )
    if (
        not re.fullmatch(r"app-[A-Za-z0-9][A-Za-z0-9._-]{0,155}", runtime_directory)
        or Path(runtime_directory).name != runtime_directory
    ):
        raise UpdateContractError(f"{label} has an invalid runtime_directory")
    published = _parse_utc(row["published_at"], f"{label} published_at")
    notes = _require_text(row["release_notes"], f"{label} release_notes", maximum=4000)
    formal = _require_bool(row["formal_release"], f"{label} formal_release")
    data_schema = _require_int(row["data_schema"], f"{label} data_schema", minimum=1, maximum=65535)
    compatible_min = _require_int(
        row["compatible_data_schema_min"],
        f"{label} compatible_data_schema_min",
        minimum=1,
        maximum=65535,
    )
    compatible_max = _require_int(
        row["compatible_data_schema_max"],
        f"{label} compatible_data_schema_max",
        minimum=compatible_min,
        maximum=65535,
    )
    if not compatible_min <= data_schema <= compatible_max:
        raise UpdateContractError(
            f"{label} cannot read its own data schema"
        )
    minimum_updater = SemanticVersion.parse(
        row["min_updater_version"], f"{label} min_updater_version"
    )
    installer_value = row["installer"]
    launcher = None
    if isinstance(installer_value, dict):
        installer_value = dict(installer_value)
        launcher_value = installer_value.pop("launcher_sha256", None)
        if launcher_value is not None:
            launcher = _require_digest(launcher_value, f"{label} native launcher sha256")
    if not authenticode_required and launcher is None:
        raise UpdateContractError(f"{label} requires a signed native launcher digest")
    installer_row = _require_exact_fields(
        installer_value,
        {"url", "size", "sha256", "publisher_certificate_sha256"},
        f"{label} installer",
    )
    installer_url = _validated_url(
        installer_row["url"],
        f"{label} installer URL",
        allow_test_http=allow_test_http,
    )
    host = (urlsplit(installer_url).hostname or "").casefold()
    if host not in download_hosts:
        raise UpdateContractError(f"{label} installer host is not declared")
    installer_size = _require_int(
        installer_row["size"],
        f"{label} installer size",
        minimum=1,
        maximum=installer_limit,
    )
    installer_digest = _require_digest(
        installer_row["sha256"], f"{label} installer sha256"
    )
    publisher_value = installer_row["publisher_certificate_sha256"]
    publisher = (
        None if publisher_value is None and not authenticode_required
        else _require_digest(publisher_value, f"{label} installer publisher")
    )
    if ((authenticode_required and expected_publisher is None)
            or (expected_publisher is not None and publisher != expected_publisher)):
        raise UpdateContractError(f"{label} installer publisher is unexpected")
    return ReleaseEntry(
        version=version,
        version_text=version_text,
        windows_version=windows_version,
        build_id=build_id,
        runtime_directory=runtime_directory,
        published_at=published,
        release_notes=notes,
        formal_release=formal,
        data_schema=data_schema,
        compatible_data_schema_min=compatible_min,
        compatible_data_schema_max=compatible_max,
        min_updater_version=minimum_updater,
        installer=InstallerArtifact(
            installer_url,
            installer_size,
            installer_digest,
            publisher,
            launcher,
        ),
    )


def release_identities(releases: Iterable[ReleaseEntry]) -> tuple[str, ...]:
    """Return stable display/log identities without exposing download URLs."""

    return tuple(release.identity for release in releases)
