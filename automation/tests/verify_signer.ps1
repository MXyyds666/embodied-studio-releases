[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Signer)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('es-cloud-signer-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$start = $null
try {
    $p = $key.ExportParameters($false)
    $blob = '4543533120000000' + [Convert]::ToHexString($p.Q.X) + [Convert]::ToHexString($p.Q.Y)
    $trust = [ordered]@{schema_version=1;keys=@([ordered]@{id='embodied-studio-cloud-catalog-20261029';public_blob_hex=$blob})}
    $public = Join-Path $fixture 'trust.json'
    $payload = Join-Path $fixture 'payload.json'
    $signature = Join-Path $fixture 'payload.sig'
    $trust | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $public -Encoding utf8
    [IO.File]::WriteAllBytes($payload,[Text.Encoding]::UTF8.GetBytes('public fixture challenge'))
    $start = [Diagnostics.ProcessStartInfo]::new('pwsh')
    foreach ($argument in @('-NoProfile','-File',$Signer,'-InputFile',$payload,'-PublicTrustFile',$public,'-SignatureFile',$signature)) { $start.ArgumentList.Add($argument) }
    $start.Environment['ES_CATALOG_SIGNING_KEY_PEM'] = $key.ExportPkcs8PrivateKeyPem()
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($start)
    $null = $process.StandardOutput.ReadToEnd(); $errorText = $process.StandardError.ReadToEnd()
    if (!$process.WaitForExit(60000) -or $process.ExitCode -ne 0) { throw ('Fixture signer failed: ' + $errorText) }
    $bytes = [IO.File]::ReadAllBytes($signature)
    if ($bytes.Length -ne 64 -or !$key.VerifyData([IO.File]::ReadAllBytes($payload),$bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) { throw 'Fixture signature verification failed.' }
    $trust.keys[0].public_blob_hex = ('ff' * 72)
    $trust | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $public -Encoding utf8
    $start.ArgumentList[$start.ArgumentList.Count-1] = (Join-Path $fixture 'wrong.sig')
    $process = [Diagnostics.Process]::Start($start)
    $null = $process.StandardOutput.ReadToEnd(); $null = $process.StandardError.ReadToEnd()
    if (!$process.WaitForExit(60000) -or $process.ExitCode -eq 0) { throw 'Wrong public key was not rejected.' }
    '{"status":"passed","private_key_written_to_disk":false,"wrong_public_key_rejected":true}'
} finally {
    $key.Dispose()
    if ($start) { $start.Environment.Remove('ES_CATALOG_SIGNING_KEY_PEM') | Out-Null }
    # This unique fixture contains only this test's public input and signature.
    $resolved = [IO.Path]::GetFullPath($fixture)
    if ($resolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($resolved).StartsWith('es-cloud-signer-test-')) { [IO.Directory]::Delete($resolved,$true) }
}
