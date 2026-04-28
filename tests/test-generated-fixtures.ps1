# SPDX-License-Identifier: MIT
#
# Build/install the extension in the local Ghidra container, generate synthetic
# CRO/CRS fixtures, and run payload-free headless structure exports.
#
# Usage:
#   pwsh tests/test-generated-fixtures.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string] $Container = "ghidra-mcp"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$FixtureDir = Join-Path $RepoRoot ".local-test\generated"
$OutDir = Join-Path $RepoRoot ".local-test\structure-export"

pwsh (Join-Path $RepoRoot "tests\build-extension.ps1") -Container $Container

$installScript = @'
set -euo pipefail
zip_path="$(ls -1 /tmp/ghidra-ctr-loader-build/ghidra-ctr-loader/dist/*ghidra-ctr-loader.zip | tail -1)"
ext_dir="/opt/ghidra/Ghidra/Extensions/ghidra-ctr-loader"
rm -rf "$ext_dir"
mkdir -p "$ext_dir"
unzip -q "$zip_path" -d "$ext_dir"
'@
docker exec $Container bash -lc $installScript

pwsh (Join-Path $RepoRoot "tests\New-SyntheticCroFixture.ps1") -OutDir $FixtureDir

foreach ($fixture in @("synthetic.cro", "synthetic.crs")) {
    $inputPath = Join-Path $FixtureDir $fixture
    $outPath = Join-Path $OutDir "$fixture.structure.json"
    pwsh (Join-Path $RepoRoot "tests\export-structure.ps1") `
        -InputPath $inputPath `
        -OutPath $outPath `
        -Container $Container
}

Write-Host "Generated fixture smoke tests passed"
