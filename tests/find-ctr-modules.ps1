# SPDX-License-Identifier: MIT
#
# Find CRO/CRS candidates from payload-safe ExeFS and RomFS manifests.
#
# Usage:
#   pwsh tests/find-ctr-modules.ps1 `
#     -ExeFsManifest ".local-test\exefs\game\manifest.structure.json" `
#     -RomFsManifest ".local-test\romfs-list\game.romfs.structure.json"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string] $ExeFsManifest = "",

    [Parameter(Mandatory=$false)]
    [string] $RomFsManifest = "",

    [Parameter(Mandatory=$false)]
    [string] $OutPath = "",

    [Parameter(Mandatory=$false)]
    [string] $OutDir = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RepoRoot ".local-test\module-discovery"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if ([string]::IsNullOrWhiteSpace($OutPath)) {
    $OutPath = Join-Path $OutDir "ctr-modules.structure.json"
}

$candidates = New-Object System.Collections.Generic.List[object]

if (-not [string]::IsNullOrWhiteSpace($ExeFsManifest)) {
    if (-not (Test-Path $ExeFsManifest)) {
        throw "ExeFS manifest not found: $ExeFsManifest"
    }
    $exefs = Get-Content -LiteralPath $ExeFsManifest -Raw | ConvertFrom-Json
    foreach ($file in @($exefs.files)) {
        $ext = [IO.Path]::GetExtension($file.name).ToLowerInvariant()
        if ($ext -eq ".cro" -or $ext -eq ".crs") {
            $size = if ($null -ne $file.extracted_size) { $file.extracted_size } else { $file.size }
            $candidates.Add([pscustomobject]@{
                source = "exefs"
                path = "/exefs/$($file.name)"
                extension = $ext
                size = $size
            }) | Out-Null
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($RomFsManifest)) {
    if (-not (Test-Path $RomFsManifest)) {
        throw "RomFS manifest not found: $RomFsManifest"
    }
    $romfs = Get-Content -LiteralPath $RomFsManifest -Raw | ConvertFrom-Json
    foreach ($file in @($romfs.files)) {
        $ext = [IO.Path]::GetExtension($file.path).ToLowerInvariant()
        if ($ext -eq ".cro" -or $ext -eq ".crs") {
            $candidates.Add([pscustomobject]@{
                source = "romfs"
                path = $file.path
                extension = $ext
                size = $file.size
            }) | Out-Null
        }
    }
}

$summary = [pscustomobject]@{
    candidate_count = $candidates.Count
    cro_count = @($candidates | Where-Object extension -eq ".cro").Count
    crs_count = @($candidates | Where-Object extension -eq ".crs").Count
    candidates = @($candidates | Sort-Object source, path)
}

$summary | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutPath -Encoding utf8
Write-Host "Wrote $OutPath"
