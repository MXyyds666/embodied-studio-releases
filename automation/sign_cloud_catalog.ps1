[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$PublicTrustFile,
    [Parameter(Mandatory = $true)][string]$SignatureFile,
    [switch]$PreflightOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($env:ES_CATALOG_SIGNING_KEY_PEM)) { throw 'Cloud signing Secret is missing.' }
$trust = Get-Content -Raw -LiteralPath $PublicTrustFile | ConvertFrom-Json
$selected = @($trust.keys | Where-Object { $_.id -eq 'embodied-studio-cloud-catalog-20261029' })
if ($selected.Count -ne 1 -or $selected[0].public_blob_hex -notmatch '^[0-9a-fA-F]{144}$') { throw 'Expected pinned cloud P256 public key.' }
$item = Get-Item -LiteralPath $InputFile
if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 524288) { throw 'Signing requires a bounded regular catalog file.' }
if (Test-Path -LiteralPath $SignatureFile) { throw 'Do not overwrite an existing signature.' }
# C# handles span-based .NET key import. The compiled source contains no key.
Add-Type -TypeDefinition @'
using System;
using System.Security.Cryptography;
public static class CloudCatalogSigner {
    public static byte[] Sign(string pem, byte[] payload, string expectedBlob, bool preflight) {
        using (ECDsa key = ECDsa.Create()) {
            key.ImportFromPem(pem);
            if (key.KeySize != 256) throw new CryptographicException("Expected ECDSA P256");
            ECParameters parameters = key.ExportParameters(false);
            if (parameters.Curve.Oid.Value != "1.2.840.10045.3.1.7") throw new CryptographicException("Wrong signing curve");
            string actual = "4543533120000000" + Convert.ToHexString(parameters.Q.X) + Convert.ToHexString(parameters.Q.Y);
            if (!String.Equals(actual, expectedBlob, StringComparison.OrdinalIgnoreCase)) throw new CryptographicException("Cloud key differs from pinned public trust");
            if (preflight) return Array.Empty<byte>();
            byte[] signature = key.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (signature.Length != 64 || !key.VerifyData(payload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new CryptographicException("P1363 signature self-check failed");
            return signature;
        }
    }
}
'@
try {
    $signature = [CloudCatalogSigner]::Sign($env:ES_CATALOG_SIGNING_KEY_PEM, [IO.File]::ReadAllBytes($item.FullName), $selected[0].public_blob_hex, [bool]$PreflightOnly)
    if (!$PreflightOnly) { [IO.File]::WriteAllBytes([IO.Path]::GetFullPath($SignatureFile), $signature) }
    [ordered]@{status='passed';key_id='embodied-studio-cloud-catalog-20261029';format='ECDSA-P256-SHA256-P1363';preflight=[bool]$PreflightOnly;private_key_written_to_disk=$false} | ConvertTo-Json -Compress
} finally { $env:ES_CATALOG_SIGNING_KEY_PEM = $null }
