"""Windows release-signature verification for host application updates.

Only public key material is accepted here.  Catalogs use the same Windows CNG
ECDSA-P256 public blob format as the packaged-runtime integrity verifier.  An
installer must independently pass Authenticode verification, match the pinned
publisher certificate SHA-256 digest, and contain a timestamp countersignature.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Iterable

from embodied_studio.application.version_management import UpdateTrustKey


_PUBLISHER_DIGEST = re.compile(r"^[0-9a-fA-F]{64}$")
_POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$target = $env:EMBODIED_UPDATE_AUTHENTICODE_TARGET
if ([string]::IsNullOrWhiteSpace($target)) { throw 'missing target' }
$signature = Get-AuthenticodeSignature -LiteralPath $target
$digest = $null
if ($null -ne $signature.SignerCertificate) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = (($sha256.ComputeHash($signature.SignerCertificate.RawData) |
            ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha256.Dispose()
    }
}
[pscustomobject]@{
    status = [string]$signature.Status
    signer_sha256 = $digest
    timestamped = ($null -ne $signature.TimeStamperCertificate)
} | ConvertTo-Json -Compress
""".strip()


class UpdateSecurityError(RuntimeError):
    """Raised when update cryptographic verification cannot be trusted."""


@dataclass(frozen=True, slots=True)
class AuthenticodeIdentity:
    publisher_certificate_sha256: str
    timestamped: bool


def _check_ntstatus(status: int, operation: str) -> None:
    if status < 0:
        raise UpdateSecurityError(
            f"Windows CNG {operation} failed: 0x{status & 0xFFFFFFFF:08x}"
        )


def verify_catalog_signature(
    payload: bytes,
    signature: bytes,
    trust_keys: Iterable[UpdateTrustKey],
) -> str:
    """Verify a detached 64-byte P1363 ECDSA-P256 signature.

    Returns the matching public key id.  The function fails closed off Windows,
    for malformed input, or when no configured key verifies the payload.
    """

    keys = tuple(trust_keys)
    if os.name != "nt":
        raise UpdateSecurityError("catalog signature verification requires Windows")
    if not payload:
        raise UpdateSecurityError("catalog payload is empty")
    if len(signature) != 64:
        raise UpdateSecurityError("catalog signature must be 64-byte P1363 ECDSA")
    if not 1 <= len(keys) <= 4:
        raise UpdateSecurityError("catalog trust requires one to four public keys")

    bcrypt = ctypes.WinDLL("bcrypt.dll", winmode=0x800)
    handle = wintypes.HANDLE
    pointer = ctypes.c_void_p
    unsigned = wintypes.ULONG
    bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
        ctypes.POINTER(handle),
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        unsigned,
    ]
    bcrypt.BCryptOpenAlgorithmProvider.restype = wintypes.LONG
    bcrypt.BCryptImportKeyPair.argtypes = [
        handle,
        handle,
        wintypes.LPCWSTR,
        ctypes.POINTER(handle),
        pointer,
        unsigned,
        unsigned,
    ]
    bcrypt.BCryptImportKeyPair.restype = wintypes.LONG
    bcrypt.BCryptVerifySignature.argtypes = [
        handle,
        pointer,
        pointer,
        unsigned,
        pointer,
        unsigned,
        unsigned,
    ]
    bcrypt.BCryptVerifySignature.restype = wintypes.LONG
    bcrypt.BCryptDestroyKey.argtypes = [handle]
    bcrypt.BCryptDestroyKey.restype = wintypes.LONG
    bcrypt.BCryptCloseAlgorithmProvider.argtypes = [handle, unsigned]
    bcrypt.BCryptCloseAlgorithmProvider.restype = wintypes.LONG

    algorithm = handle()
    _check_ntstatus(
        bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(algorithm), "ECDSA_P256", None, 0
        ),
        "provider open",
    )
    digest_buffer = ctypes.create_string_buffer(hashlib.sha256(payload).digest(), 32)
    signature_buffer = ctypes.create_string_buffer(signature, len(signature))
    try:
        for key in keys:
            if (
                len(key.public_blob) != 72
                or key.public_blob[:8] != b"ECS1\x20\x00\x00\x00"
            ):
                raise UpdateSecurityError("invalid ECDSA-P256 public key blob")
            key_buffer = ctypes.create_string_buffer(key.public_blob, 72)
            key_handle = handle()
            try:
                _check_ntstatus(
                    bcrypt.BCryptImportKeyPair(
                        algorithm,
                        None,
                        "ECCPUBLICBLOB",
                        ctypes.byref(key_handle),
                        key_buffer,
                        72,
                        0,
                    ),
                    "public key import",
                )
                status = bcrypt.BCryptVerifySignature(
                    key_handle,
                    None,
                    digest_buffer,
                    32,
                    signature_buffer,
                    64,
                    0,
                )
                if status == 0:
                    return key.key_id
            finally:
                if key_handle:
                    bcrypt.BCryptDestroyKey(key_handle)
    finally:
        if algorithm:
            bcrypt.BCryptCloseAlgorithmProvider(algorithm, 0)
    raise UpdateSecurityError("catalog signature is not trusted")


def _powershell_path() -> Path:
    system_root = os.environ.get("SystemRoot")
    if os.name != "nt" or not system_root:
        raise UpdateSecurityError("Authenticode verification requires Windows")
    executable = (
        Path(system_root)
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    if not executable.is_file():
        raise UpdateSecurityError("system Windows PowerShell is unavailable")
    return executable


def verify_installer_authenticode(
    installer: Path,
    expected_publisher_sha256: str,
    *,
    timeout_seconds: int = 30,
) -> AuthenticodeIdentity:
    """Require a valid, timestamped installer from the pinned publisher."""

    if not _PUBLISHER_DIGEST.fullmatch(expected_publisher_sha256):
        raise UpdateSecurityError("invalid expected publisher certificate digest")
    target = installer.resolve(strict=True)
    if not target.is_file() or target.suffix.casefold() != ".exe":
        raise UpdateSecurityError("update installer must be an existing EXE file")
    if not 1 <= timeout_seconds <= 120:
        raise UpdateSecurityError("invalid Authenticode verification timeout")

    powershell = _powershell_path()
    environment = os.environ.copy()
    # The caller may use PowerShell 7 or custom modules. Load the verifier
    # only from the system Windows PowerShell module directory.
    environment["PSMODULEPATH"] = str(powershell.parent / "Modules")
    environment["EMBODIED_UPDATE_AUTHENTICODE_TARGET"] = str(target)
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0
    try:
        result = subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "AllSigned",
                "-Command",
                _POWERSHELL_SCRIPT,
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_seconds,
            startupinfo=startupinfo,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise UpdateSecurityError("Authenticode verification could not run") from error
    if result.returncode != 0 or result.stderr:
        raise UpdateSecurityError("Authenticode verification failed")
    try:
        document = json.loads(result.stdout.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UpdateSecurityError("invalid Authenticode verifier response") from error
    if not isinstance(document, dict) or set(document) != {
        "status",
        "signer_sha256",
        "timestamped",
    }:
        raise UpdateSecurityError("invalid Authenticode verifier response")
    digest = document["signer_sha256"]
    if (
        document["status"] != "Valid"
        or not isinstance(digest, str)
        or not _PUBLISHER_DIGEST.fullmatch(digest)
        or digest.casefold() != expected_publisher_sha256.casefold()
        or document["timestamped"] is not True
    ):
        raise UpdateSecurityError(
            "installer signature, publisher, or timestamp is not trusted"
        )
    return AuthenticodeIdentity(digest.casefold(), True)


__all__ = [
    "AuthenticodeIdentity",
    "UpdateSecurityError",
    "verify_catalog_signature",
    "verify_installer_authenticode",
]
