# SPDX-License-Identifier: MIT
#
# Import a decompressed private 3DS .code file as raw ARM, remap it using the
# payload-free NCCH code-set manifest, and export structural JSON.
#
# Usage:
#   pwsh tests/export-code-set-structure.ps1 `
#     -CodePath ".local-test\exefs\game\.code" `
#     -ManifestPath ".local-test\exefs\game\manifest.structure.json"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $CodePath,

    [Parameter(Mandatory=$true)]
    [string] $ManifestPath,

    [Parameter(Mandatory=$false)]
    [string] $OutPath = "",

    [Parameter(Mandatory=$false)]
    [string] $OutDir = "",

    [Parameter(Mandatory=$false)]
    [string] $Container = "ghidra-mcp"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $CodePath)) {
    throw "Code path not found: $CodePath"
}
if (-not (Test-Path $ManifestPath)) {
    throw "Manifest path not found: $ManifestPath"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RepoRoot ".local-test\structure-export"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if ([string]::IsNullOrWhiteSpace($OutPath)) {
    $stem = Split-Path -Leaf (Split-Path -Parent $CodePath)
    if ([string]::IsNullOrWhiteSpace($stem)) {
        $stem = [IO.Path]::GetFileNameWithoutExtension($CodePath)
    }
    $stem = $stem -replace '[^A-Za-z0-9_.-]', '_'
    $OutPath = Join-Path $OutDir "$stem.code-set.structure.json"
}

$safeStem = [IO.Path]::GetFileNameWithoutExtension($OutPath) -replace '[^A-Za-z0-9_.-]', '_'
$runId = [Guid]::NewGuid().ToString("N")
$containerWork = "/tmp/ctr-code-set-$runId"
$headlessLog = Join-Path $OutDir "$safeStem.headless.log"

try {
    docker exec $Container bash -lc "rm -rf $containerWork && mkdir -p $containerWork/scripts $containerWork/input $containerWork/proj" | Out-Null
    docker cp (Join-Path $RepoRoot "tests\MapCtrCodeSet.java") "${Container}:$containerWork/scripts/" | Out-Null
    docker cp (Join-Path $RepoRoot "tests\ExportCtrStructureJson.java") "${Container}:$containerWork/scripts/" | Out-Null
    docker cp $CodePath "${Container}:$containerWork/input/input.code" | Out-Null
    docker cp $ManifestPath "${Container}:$containerWork/input/manifest.structure.json" | Out-Null

    $raw = docker exec $Container bash -lc "/opt/ghidra/support/analyzeHeadless $containerWork/proj export -import $containerWork/input/input.code -processor 'ARM:LE:32:v7' -cspec default -scriptPath $containerWork/scripts -preScript MapCtrCodeSet.java $containerWork/input/manifest.structure.json -postScript ExportCtrStructureJson.java -deleteProject" 2>&1
    $raw | Out-File -FilePath $headlessLog -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw "analyzeHeadless failed; see $headlessLog"
    }

    $jsonLine = $raw | Select-String -Pattern '^INFO  ExportCtrStructureJson.java> JSON: ' | Select-Object -Last 1
    if (-not $jsonLine) {
        $jsonLine = $raw | Select-String -Pattern '^JSON: ' | Select-Object -Last 1
    }
    if (-not $jsonLine -or $jsonLine.Line -notmatch 'JSON:\s*(\{.*\})') {
        throw "No JSON marker found; see $headlessLog"
    }

    $Matches[1] | ConvertFrom-Json | ConvertTo-Json -Depth 20 |
        Out-File -FilePath $OutPath -Encoding utf8
    Write-Host "Wrote $OutPath"
}
finally {
    docker exec $Container bash -lc "rm -rf $containerWork" 2>$null | Out-Null
}
