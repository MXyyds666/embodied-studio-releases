"""Bounded HTTPS client for signed host-application update catalogs/packages."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, HTTPSHandler

from embodied_studio.application.version_management import (
    ReleaseEntry,
    UpdateCatalog,
    UpdateConfiguration,
    UpdateContractError,
)
from embodied_studio.infrastructure.update_security import verify_catalog_signature


_CHUNK_BYTES = 64 * 1024
_SIGNATURE_BYTES = 64
_PARTIAL_METADATA_MAX_BYTES = 4096
_SAFE_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")
_CONTENT_RANGE = re.compile(r"^bytes (\d+)-(\d+)/(\d+)$")
_RETRYABLE_HTTP_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


class UpdateNetworkError(RuntimeError):
    """Raised when a remote update resource violates the transport contract."""


class UpdateCancelled(UpdateNetworkError):
    """Raised when the caller cancels a bounded network operation."""


class _RetryableUpdateNetworkError(UpdateNetworkError):
    """Internal marker for a bounded, idempotent GET retry."""


class _ResumeUnavailable(UpdateNetworkError):
    """Internal marker for a stale byte-range request."""


@dataclass(frozen=True, slots=True)
class FetchedCatalog:
    catalog: UpdateCatalog
    payload: bytes
    signature: bytes
    trusted_key_id: str


@dataclass(frozen=True, slots=True)
class DownloadedInstaller:
    path: Path
    size: int
    sha256: str
    resumed: bool


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").casefold()


def _validate_remote_url(
    url: str,
    *,
    allowed_hosts: frozenset[str],
    allow_test_http: bool,
) -> None:
    parts = urlsplit(url)
    host = (parts.hostname or "").casefold()
    allowed_scheme = parts.scheme == "https" or (
        allow_test_http
        and parts.scheme == "http"
        and host in {"127.0.0.1", "::1", "localhost"}
    )
    if (
        not allowed_scheme
        or host not in allowed_hosts
        or parts.username is not None
        or parts.password is not None
        or bool(parts.fragment)
    ):
        raise UpdateNetworkError("update URL or redirect is not permitted")


class _GuardedRedirectHandler(HTTPRedirectHandler):
    def __init__(
        self,
        allowed_hosts: frozenset[str],
        *,
        allow_test_http: bool,
    ) -> None:
        super().__init__()
        self._allowed_hosts = allowed_hosts
        self._allow_test_http = allow_test_http

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        absolute = urljoin(request.full_url, new_url)
        _validate_remote_url(
            absolute,
            allowed_hosts=self._allowed_hosts,
            allow_test_http=self._allow_test_http,
        )
        return super().redirect_request(
            request,
            file_pointer,
            code,
            message,
            headers,
            absolute,
        )


def _opener(allowed_hosts: frozenset[str], *, allow_test_http: bool):
    context = ssl.create_default_context()
    return build_opener(
        HTTPSHandler(context=context),
        _GuardedRedirectHandler(
            allowed_hosts,
            allow_test_http=allow_test_http,
        ),
    )


def _content_length(headers) -> int | None:
    value = headers.get("Content-Length")
    if value is None:
        return None
    try:
        parsed = int(value, 10)
    except (TypeError, ValueError) as error:
        raise UpdateNetworkError("invalid Content-Length") from error
    if parsed < 0:
        raise UpdateNetworkError("invalid Content-Length")
    return parsed


def _require_identity_encoding(headers) -> None:
    encoding = (headers.get("Content-Encoding") or "identity").casefold()
    if encoding != "identity":
        raise UpdateNetworkError("compressed update responses are not accepted")


def _cancelled(callback: Callable[[], bool] | None) -> None:
    if callback is not None and callback():
        raise UpdateCancelled("update operation cancelled")


def _read_bounded(
    response,
    *,
    maximum: int,
    cancelled: Callable[[], bool] | None,
) -> bytes:
    _require_identity_encoding(response.headers)
    declared = _content_length(response.headers)
    if declared is not None and declared > maximum:
        raise UpdateNetworkError("update response exceeds configured size")
    chunks: list[bytes] = []
    total = 0
    while True:
        _cancelled(cancelled)
        chunk = response.read(min(_CHUNK_BYTES, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise UpdateNetworkError("update response exceeds configured size")
    if declared is not None and total != declared:
        raise _RetryableUpdateNetworkError("update response was truncated")
    return b"".join(chunks)


def _atomic_json(path: Path, document: dict[str, object]) -> None:
    raw = (json.dumps(document, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _strong_etag(headers) -> str | None:
    value = headers.get("ETag")
    if (
        not isinstance(value, str)
        or not value.startswith('"')
        or not value.endswith('"')
        or value.startswith('W/')
        or len(value) > 256
        or any(ord(character) < 32 for character in value)
    ):
        return None
    return value


def installer_file_name(release: ReleaseEntry) -> str:
    version = _SAFE_COMPONENT.sub("-", release.version_text).strip(".-_")
    build_id = _SAFE_COMPONENT.sub("-", release.build_id).strip(".-_")
    if not version or not build_id:
        raise UpdateNetworkError("release identity cannot form an installer name")
    # Keep the persisted basename inside the update-state contract while the
    # digest suffix preserves uniqueness after truncation.
    return (
        f"EmbodiedStudio-{version[:48]}-{build_id[:64]}-"
        f"{release.installer.sha256[:16]}.exe"
    )


class UpdateHttpClient:
    def __init__(
        self,
        configuration: UpdateConfiguration,
        *,
        allow_test_http: bool = False,
        timeout_seconds: int = 30,
        retry_attempts: int = 3,
        retry_backoff_seconds: float = 0.25,
    ) -> None:
        if not 1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 1 and 120")
        if not 1 <= retry_attempts <= 5:
            raise ValueError("retry_attempts must be between 1 and 5")
        if not 0 <= retry_backoff_seconds <= 5:
            raise ValueError("retry_backoff_seconds must be between 0 and 5")
        self.configuration = configuration
        self.allow_test_http = allow_test_http
        self.timeout_seconds = timeout_seconds
        self.retry_attempts = retry_attempts
        self.retry_backoff_seconds = retry_backoff_seconds

    def _wait_before_retry(
        self,
        failed_attempt: int,
        *,
        cancelled: Callable[[], bool] | None,
    ) -> None:
        """Apply a short bounded backoff while remaining cancel responsive."""

        delay = self.retry_backoff_seconds * (2 ** max(0, failed_attempt - 1))
        deadline = time.monotonic() + delay
        while True:
            _cancelled(cancelled)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.05, remaining))

    def _request_bytes(
        self,
        url: str,
        *,
        maximum: int,
        allowed_hosts: frozenset[str],
        cancelled: Callable[[], bool] | None,
    ) -> bytes:
        _validate_remote_url(
            url,
            allowed_hosts=allowed_hosts,
            allow_test_http=self.allow_test_http,
        )
        last_error: _RetryableUpdateNetworkError | None = None
        for attempt in range(1, self.retry_attempts + 1):
            _cancelled(cancelled)
            try:
                return self._request_bytes_once(
                    url,
                    maximum=maximum,
                    allowed_hosts=allowed_hosts,
                    cancelled=cancelled,
                )
            except UpdateCancelled:
                raise
            except _RetryableUpdateNetworkError as error:
                last_error = error
                if attempt >= self.retry_attempts:
                    break
                self._wait_before_retry(attempt, cancelled=cancelled)
        raise UpdateNetworkError(
            "update resource request failed after bounded retries"
        ) from last_error

    def _request_bytes_once(
        self,
        url: str,
        *,
        maximum: int,
        allowed_hosts: frozenset[str],
        cancelled: Callable[[], bool] | None,
    ) -> bytes:
        request = Request(
            url,
            headers={
                "Accept": "application/octet-stream, application/json",
                "Accept-Encoding": "identity",
                "Cache-Control": "no-cache",
                "User-Agent": "EmbodiedStudio-Updater/1",
            },
            method="GET",
        )
        try:
            with _opener(
                allowed_hosts,
                allow_test_http=self.allow_test_http,
            ).open(request, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise UpdateNetworkError(
                        f"unexpected update HTTP status: {response.status}"
                    )
                _validate_remote_url(
                    response.geturl(),
                    allowed_hosts=allowed_hosts,
                    allow_test_http=self.allow_test_http,
                )
                return _read_bounded(
                    response,
                    maximum=maximum,
                    cancelled=cancelled,
                )
        except (UpdateCancelled, UpdateNetworkError):
            raise
        except HTTPError as error:
            status = error.code
            error.close()
            if status in _RETRYABLE_HTTP_STATUS:
                raise _RetryableUpdateNetworkError(
                    f"temporary update HTTP status: {status}"
                ) from error
            raise UpdateNetworkError(
                f"unexpected update HTTP status: {status}"
            ) from error
        except (URLError, HTTPException, TimeoutError, OSError) as error:
            raise _RetryableUpdateNetworkError(
                "update resource request failed"
            ) from error

    def fetch_catalog(
        self,
        *,
        highest_seen_sequence: int = 0,
        cancelled: Callable[[], bool] | None = None,
    ) -> FetchedCatalog:
        config = self.configuration
        if (
            not config.enabled
            or config.catalog_url is None
            or config.catalog_signature_url is None
        ):
            raise UpdateNetworkError("online updates are disabled")
        hosts = frozenset(
            {_host(config.catalog_url), _host(config.catalog_signature_url)}
        )
        payload = self._request_bytes(
            config.catalog_url,
            maximum=config.catalog_max_bytes,
            allowed_hosts=hosts,
            cancelled=cancelled,
        )
        signature = self._request_bytes(
            config.catalog_signature_url,
            maximum=_SIGNATURE_BYTES,
            allowed_hosts=hosts,
            cancelled=cancelled,
        )
        if len(signature) != _SIGNATURE_BYTES:
            raise UpdateNetworkError("catalog signature has an invalid size")
        trusted_key = verify_catalog_signature(
            payload,
            signature,
            config.public_trust,
        )
        try:
            catalog = UpdateCatalog.from_bytes(
                payload,
                configuration=config,
                highest_seen_sequence=highest_seen_sequence,
                allow_test_http=self.allow_test_http,
            )
        except UpdateContractError as error:
            raise UpdateNetworkError("signed update catalog is invalid") from error
        return FetchedCatalog(catalog, payload, signature, trusted_key)

    def download_installer(
        self,
        release: ReleaseEntry,
        packages_directory: Path,
        *,
        progress: Callable[[int, int], None] | None = None,
        cancelled: Callable[[], bool] | None = None,
        allowed_hosts: frozenset[str],
    ) -> DownloadedInstaller:
        config = self.configuration
        if not config.enabled:
            raise UpdateNetworkError("online updates are disabled")
        if release.installer.size > config.installer_max_bytes:
            raise UpdateNetworkError("installer exceeds configured size")
        url = release.installer.url
        _validate_remote_url(
            url,
            allowed_hosts=allowed_hosts,
            allow_test_http=self.allow_test_http,
        )
        packages_directory.mkdir(parents=True, exist_ok=True)
        target = packages_directory / installer_file_name(release)
        partial = target.with_suffix(target.suffix + ".part")
        metadata = target.with_suffix(target.suffix + ".part.json")

        if target.exists():
            size, digest = self._file_identity(target, cancelled=cancelled)
            if size == release.installer.size and digest == release.installer.sha256:
                return DownloadedInstaller(target, size, digest, False)
            target.unlink()

        last_error: _RetryableUpdateNetworkError | None = None
        for attempt in range(1, self.retry_attempts + 1):
            _cancelled(cancelled)
            resume_at, etag = self._resume_information(
                partial,
                metadata,
                release,
            )
            try:
                return self._stream_installer(
                    release,
                    target=target,
                    partial=partial,
                    metadata=metadata,
                    resume_at=resume_at,
                    etag=etag,
                    progress=progress,
                    cancelled=cancelled,
                    allowed_hosts=allowed_hosts,
                )
            except UpdateCancelled:
                self._discard_unusable_partial(
                    partial,
                    metadata,
                    expected_size=release.installer.size,
                )
                raise
            except _RetryableUpdateNetworkError as error:
                last_error = error
                self._discard_unusable_partial(
                    partial,
                    metadata,
                    expected_size=release.installer.size,
                )
                if attempt >= self.retry_attempts:
                    break
                self._wait_before_retry(attempt, cancelled=cancelled)
            except Exception:
                # A strong ETag metadata record makes a partial safe to resume.
                # A completed, unbound, or otherwise unusable payload is never
                # retained.
                self._discard_unusable_partial(
                    partial,
                    metadata,
                    expected_size=release.installer.size,
                )
                raise
        raise UpdateNetworkError(
            "installer download failed after bounded retries"
        ) from last_error

    @staticmethod
    def _discard_partial(partial: Path, metadata: Path) -> None:
        partial.unlink(missing_ok=True)
        metadata.unlink(missing_ok=True)

    @classmethod
    def _discard_unusable_partial(
        cls,
        partial: Path,
        metadata: Path,
        *,
        expected_size: int,
    ) -> None:
        try:
            resumable = (
                partial.is_file()
                and metadata.is_file()
                and 0 < partial.stat().st_size < expected_size
            )
        except OSError:
            resumable = False
        if not resumable:
            cls._discard_partial(partial, metadata)

    @staticmethod
    def _file_identity(
        path: Path,
        *,
        cancelled: Callable[[], bool] | None,
    ) -> tuple[int, str]:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            while True:
                _cancelled(cancelled)
                chunk = stream.read(_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        return size, digest.hexdigest()

    @staticmethod
    def _resume_information(
        partial: Path,
        metadata: Path,
        release: ReleaseEntry,
    ) -> tuple[int, str | None]:
        if not partial.is_file() or not metadata.is_file():
            partial.unlink(missing_ok=True)
            metadata.unlink(missing_ok=True)
            return 0, None
        try:
            metadata_size = metadata.stat().st_size
            if not 1 <= metadata_size <= _PARTIAL_METADATA_MAX_BYTES:
                raise ValueError
            document = json.loads(metadata.read_text(encoding="utf-8"))
            expected = {"url", "size", "sha256", "etag"}
            if not isinstance(document, dict) or set(document) != expected:
                raise ValueError
            etag = document["etag"]
            if (
                document["url"] != release.installer.url
                or document["size"] != release.installer.size
                or document["sha256"] != release.installer.sha256
                or not isinstance(etag, str)
                or not etag.startswith('"')
                or not etag.endswith('"')
                or etag.startswith('W/')
                or len(etag) > 256
                or any(ord(character) < 32 for character in etag)
            ):
                raise ValueError
            size = partial.stat().st_size
            if not 0 < size < release.installer.size:
                raise ValueError
            return size, etag
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            partial.unlink(missing_ok=True)
            metadata.unlink(missing_ok=True)
            return 0, None

    def _open_installer_response(
        self,
        url: str,
        *,
        headers: dict[str, str],
        allowed_hosts: frozenset[str],
    ):
        request = Request(url, headers=headers, method="GET")
        try:
            return _opener(
                allowed_hosts,
                allow_test_http=self.allow_test_http,
            ).open(request, timeout=self.timeout_seconds)
        except HTTPError as error:
            status = error.code
            error.close()
            if status == 416:
                raise _ResumeUnavailable(
                    "installer byte range is no longer available"
                ) from error
            if status in _RETRYABLE_HTTP_STATUS:
                raise _RetryableUpdateNetworkError(
                    f"temporary installer HTTP status: {status}"
                ) from error
            raise UpdateNetworkError(
                f"unexpected installer HTTP status: {status}"
            ) from error
        except (URLError, HTTPException, TimeoutError, OSError) as error:
            raise _RetryableUpdateNetworkError(
                "installer download request failed"
            ) from error

    def _stream_installer(
        self,
        release: ReleaseEntry,
        *,
        target: Path,
        partial: Path,
        metadata: Path,
        resume_at: int,
        etag: str | None,
        progress: Callable[[int, int], None] | None,
        cancelled: Callable[[], bool] | None,
        allowed_hosts: frozenset[str],
    ) -> DownloadedInstaller:
        common_headers = {
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "EmbodiedStudio-Updater/1",
        }
        headers = dict(common_headers)
        if resume_at and etag:
            headers.update(Range=f"bytes={resume_at}-", **{"If-Range": etag})
        try:
            response = self._open_installer_response(
                release.installer.url,
                headers=headers,
                allowed_hosts=allowed_hosts,
            )
        except _ResumeUnavailable:
            if not resume_at:
                raise UpdateNetworkError("unexpected installer HTTP status: 416")
            self._discard_partial(partial, metadata)
            return self._stream_installer(
                release,
                target=target,
                partial=partial,
                metadata=metadata,
                resume_at=0,
                etag=None,
                progress=progress,
                cancelled=cancelled,
                allowed_hosts=allowed_hosts,
            )
        resumed = False
        if resume_at:
            if response.status == 206:
                content_range = response.headers.get("Content-Range") or ""
                match = _CONTENT_RANGE.fullmatch(content_range)
                response_etag = _strong_etag(response.headers)
                if (
                    match is None
                    or int(match.group(1)) != resume_at
                    or int(match.group(2)) != release.installer.size - 1
                    or int(match.group(3)) != release.installer.size
                    or response_etag != etag
                ):
                    response.close()
                    self._discard_partial(partial, metadata)
                    return self._stream_installer(
                        release,
                        target=target,
                        partial=partial,
                        metadata=metadata,
                        resume_at=0,
                        etag=None,
                        progress=progress,
                        cancelled=cancelled,
                        allowed_hosts=allowed_hosts,
                    )
                resumed = True
            elif response.status == 200:
                response.close()
                partial.unlink(missing_ok=True)
                metadata.unlink(missing_ok=True)
                return self._stream_installer(
                    release,
                    target=target,
                    partial=partial,
                    metadata=metadata,
                    resume_at=0,
                    etag=None,
                    progress=progress,
                    cancelled=cancelled,
                    allowed_hosts=allowed_hosts,
                )
            else:
                response.close()
                raise UpdateNetworkError("unexpected resume HTTP status")
        elif response.status != 200:
            response.close()
            raise UpdateNetworkError("unexpected installer HTTP status")

        with response:
            _validate_remote_url(
                response.geturl(),
                allowed_hosts=allowed_hosts,
                allow_test_http=self.allow_test_http,
            )
            _require_identity_encoding(response.headers)
            declared = _content_length(response.headers)
            expected_remaining = release.installer.size - resume_at
            if declared is not None and declared != expected_remaining:
                raise UpdateNetworkError("installer Content-Length does not match catalog")
            response_etag = _strong_etag(response.headers)
            if resume_at == 0:
                if response_etag is not None:
                    _atomic_json(
                        metadata,
                        {
                            "url": release.installer.url,
                            "size": release.installer.size,
                            "sha256": release.installer.sha256,
                            "etag": response_etag,
                        },
                    )
                else:
                    metadata.unlink(missing_ok=True)

            digest = hashlib.sha256()
            written = 0
            mode = "wb"
            if resumed:
                mode = "ab"
                with partial.open("rb") as existing:
                    while True:
                        _cancelled(cancelled)
                        chunk = existing.read(_CHUNK_BYTES)
                        if not chunk:
                            break
                        digest.update(chunk)
                        written += len(chunk)
                if written != resume_at:
                    raise UpdateNetworkError("partial installer changed before resume")
            with partial.open(mode) as output:
                if progress is not None:
                    progress(written, release.installer.size)
                while True:
                    _cancelled(cancelled)
                    try:
                        chunk = response.read(_CHUNK_BYTES)
                    except (
                        URLError,
                        HTTPException,
                        TimeoutError,
                        OSError,
                    ) as error:
                        raise _RetryableUpdateNetworkError(
                            "installer transfer was interrupted"
                        ) from error
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > release.installer.size:
                        raise UpdateNetworkError("installer exceeds catalog size")
                    output.write(chunk)
                    digest.update(chunk)
                    if progress is not None:
                        progress(written, release.installer.size)
                output.flush()
                os.fsync(output.fileno())
        if written != release.installer.size:
            raise _RetryableUpdateNetworkError("installer download was truncated")
        actual_digest = digest.hexdigest()
        if actual_digest != release.installer.sha256:
            raise UpdateNetworkError("installer SHA-256 does not match catalog")
        os.replace(partial, target)
        metadata.unlink(missing_ok=True)
        return DownloadedInstaller(target, written, actual_digest, resumed)


__all__ = [
    "DownloadedInstaller",
    "FetchedCatalog",
    "UpdateCancelled",
    "UpdateHttpClient",
    "UpdateNetworkError",
    "installer_file_name",
]
