from __future__ import annotations

import base64

from .agent_package import AgentPackageManifest
from .powershell import ps_literal
from .powershell_sha256 import POWERSHELL_SHA256_FUNCTION


POWERSHELL_AGENT_PACKAGE_VERIFY_FUNCTION = rf'''
{POWERSHELL_SHA256_FUNCTION}

function Test-HmsAgentPackageTree([string]$PackageRoot, [string]$ManifestBase64) {{
  if (-not (Test-Path -LiteralPath $PackageRoot -PathType Container)) {{
    throw 'HMS Agent package root is missing'
  }}
  $rootItem = Get-Item -LiteralPath $PackageRoot -Force -ErrorAction Stop
  if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
    throw 'HMS Agent package root must not be a reparse point'
  }}

  $manifestBytes = [Convert]::FromBase64String($ManifestBase64)
  $manifestJson = [Text.Encoding]::UTF8.GetString($manifestBytes)
  $manifest = $manifestJson | ConvertFrom-Json -ErrorAction Stop
  if ([int]$manifest.schema_version -ne 2) {{ throw 'HMS Agent package manifest schema mismatch' }}
  if ([string]$manifest.platform -ne 'windows-x64') {{ throw 'HMS Agent package platform mismatch' }}
  if ([string]$manifest.entrypoint -ne 'hms-agent.exe') {{ throw 'HMS Agent package entrypoint mismatch' }}
  if ([int]$manifest.file_count -le 0 -or [int]$manifest.file_count -gt 4096) {{
    throw 'HMS Agent package manifest file count is outside safety bounds'
  }}
  if ([int64]$manifest.total_size -le 0 -or [int64]$manifest.total_size -gt 1073741824) {{
    throw 'HMS Agent package manifest total size is outside safety bounds'
  }}

  $expected = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
  foreach ($entry in @($manifest.files)) {{
    $relative = [string]$entry.path
    if ([string]::IsNullOrWhiteSpace($relative) -or $relative.Contains('\') -or $relative.StartsWith('/') -or $relative.Contains('../') -or $relative.Contains('/../') -or $relative.EndsWith('/..')) {{
      throw 'HMS Agent package manifest contains an unsafe relative path'
    }}
    if ($expected.ContainsKey($relative)) {{
      throw 'HMS Agent package manifest contains duplicate or case-colliding paths'
    }}
    $expected.Add($relative, $entry)
  }}
  if ($expected.Count -ne [int]$manifest.file_count) {{
    throw 'HMS Agent package manifest file count mismatch'
  }}

  $actual = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
  $stack = New-Object 'System.Collections.Generic.Stack[string]'
  $stack.Push($rootItem.FullName)
  while ($stack.Count -gt 0) {{
    $directory = $stack.Pop()
    foreach ($entryPath in [System.IO.Directory]::EnumerateFileSystemEntries($directory)) {{
      $item = Get-Item -LiteralPath $entryPath -Force -ErrorAction Stop
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
        throw 'HMS Agent package must not contain reparse points'
      }}
      if (($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {{
        $stack.Push($item.FullName)
        continue
      }}
      $relative = $item.FullName.Substring($rootItem.FullName.Length).TrimStart('\').Replace('\', '/')
      if ($actual.ContainsKey($relative)) {{
        throw 'HMS Agent package contains duplicate or case-colliding paths'
      }}
      $actual.Add($relative, $item.FullName)
      if ($actual.Count -gt 4096) {{ throw 'HMS Agent package file count exceeds safety bound' }}
    }}
  }}

  if ($actual.Count -ne $expected.Count) {{
    throw 'HMS Agent package tree file count differs from manifest'
  }}

  [int64]$totalSize = 0
  $entrypointHash = $null
  foreach ($key in $expected.Keys) {{
    if (-not $actual.ContainsKey($key)) {{ throw 'HMS Agent package is missing a manifested file' }}
    $expectedEntry = $expected[$key]
    $actualPath = $actual[$key]
    $actualRelative = (Get-Item -LiteralPath $actualPath -Force).FullName.Substring($rootItem.FullName.Length).TrimStart('\').Replace('\', '/')
    if ($actualRelative -cne [string]$expectedEntry.path) {{
      throw 'HMS Agent package path casing differs from manifest'
    }}
    $actualItem = Get-Item -LiteralPath $actualPath -Force -ErrorAction Stop
    if ([int64]$actualItem.Length -ne [int64]$expectedEntry.size) {{
      throw 'HMS Agent package file size mismatch'
    }}
    $hash = Get-HmsSha256 $actualPath
    if ($hash -ne ([string]$expectedEntry.sha256).ToLowerInvariant()) {{
      throw 'HMS Agent package file SHA-256 mismatch'
    }}
    $totalSize += [int64]$actualItem.Length
    if ([string]$expectedEntry.path -ceq [string]$manifest.entrypoint) {{ $entrypointHash = $hash }}
  }}
  foreach ($key in $actual.Keys) {{
    if (-not $expected.ContainsKey($key)) {{ throw 'HMS Agent package contains an unmanifested file' }}
  }}
  if ($totalSize -ne [int64]$manifest.total_size) {{ throw 'HMS Agent package total size mismatch' }}
  if ([string]::IsNullOrWhiteSpace($entrypointHash)) {{ throw 'HMS Agent package entrypoint is absent' }}

  return [pscustomobject]@{{
    file_count = [int]$actual.Count
    total_size = [int64]$totalSize
    entrypoint_sha256 = [string]$entrypointHash
  }}
}}
'''.strip()


def package_manifest_base64(manifest: AgentPackageManifest) -> str:
    manifest.validate()
    return base64.b64encode(manifest.to_json().encode("utf-8")).decode("ascii")


def package_manifest_ps_literal(manifest: AgentPackageManifest) -> str:
    return ps_literal(package_manifest_base64(manifest))
