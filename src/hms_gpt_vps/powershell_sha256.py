from __future__ import annotations


POWERSHELL_SHA256_FUNCTION = r"""
function Get-HmsSha256([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path)) { throw 'SHA-256 path is required' }
  $stream = [System.IO.File]::Open(
    $Path,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
  )
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
      $hashBytes = $sha.ComputeHash($stream)
    } finally {
      $sha.Dispose()
    }
  } finally {
    $stream.Dispose()
  }
  return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
}
""".strip()
