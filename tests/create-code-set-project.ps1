# SPDX-License-Identifier: MIT
#
# Create a persistent local Ghidra project for a decompressed private 3DS .code
# file using the payload-free NCCH code-set manifest.
#
# Usage:
#   pwsh tests/create-code-set-project.ps1 `
#     -CodePath ".local-test\exefs\game\.code" `
#     -ManifestPath ".local-test\exefs\game\manifest.structure.json"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $CodePath,

    [Parameter(Mandatory=$true)]
    [string] $ManifestPath,

    [Parameter(Mandatory=$false)]
    [string] $ProjectName = "",

    [Parameter(Mandatory=$false)]
    [string] $OutDir = "",

    [Parameter(Mandatory=$false)]
    [switch] $InitializeBss,

    [Parameter(Mandatory=$false)]
    [switch] $DisableSwitchAnalysis,

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
    $OutDir = Join-Path $RepoRoot ".local-test\ghidra-projects"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if ([string]::IsNullOrWhiteSpace($ProjectName)) {
    $stem = Split-Path -Leaf (Split-Path -Parent $CodePath)
    if ([string]::IsNullOrWhiteSpace($stem)) {
        $stem = "ctr-code-set"
    }
    $ProjectName = $stem -replace '[^A-Za-z0-9_.-]', '_'
}

$runId = [Guid]::NewGuid().ToString("N")
$containerWork = "/tmp/ctr-project-$runId"
$containerProjectRoot = "$containerWork/proj"
$containerProjectName = $ProjectName
$localProjectDir = Join-Path $OutDir $ProjectName
$headlessLog = Join-Path $OutDir "$ProjectName.headless.log"

if (Test-Path $localProjectDir) {
    Remove-Item -Recurse -Force $localProjectDir
}

try {
    docker exec $Container bash -lc "rm -rf $containerWork && mkdir -p $containerWork/scripts $containerWork/input $containerProjectRoot" | Out-Null
    docker cp (Join-Path $RepoRoot "tests\MapCtrCodeSet.java") "${Container}:$containerWork/scripts/" | Out-Null
    docker cp $CodePath "${Container}:$containerWork/input/input.code" | Out-Null
    docker cp $ManifestPath "${Container}:$containerWork/input/manifest.structure.json" | Out-Null

    $mapperArgs = "$containerWork/input/manifest.structure.json"
    if ($InitializeBss) {
        $mapperArgs += " --init-bss"
    }
    if ($DisableSwitchAnalysis) {
        $mapperArgs += " --disable-switch-analysis"
    }

    $raw = docker exec $Container bash -lc "/opt/ghidra/support/analyzeHeadless $containerProjectRoot $containerProjectName -import $containerWork/input/input.code -processor 'ARM:LE:32:v7' -cspec default -scriptPath $containerWork/scripts -preScript MapCtrCodeSet.java $mapperArgs" 2>&1
    $raw | Out-File -FilePath $headlessLog -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw "analyzeHeadless failed; see $headlessLog"
    }

    New-Item -ItemType Directory -Force -Path $localProjectDir | Out-Null
    docker cp "${Container}:$containerProjectRoot/." $localProjectDir | Out-Null
    Write-Host "Wrote project to $localProjectDir"
    Write-Host "Wrote $headlessLog"
}
finally {
    docker exec $Container bash -lc "rm -rf $containerWork" 2>$null | Out-Null
}
