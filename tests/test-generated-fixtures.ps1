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
pwsh (Join-Path $RepoRoot "tests\New-SyntheticCxiFixture.ps1") -OutDir $FixtureDir

foreach ($fixture in @("synthetic.cro", "synthetic.crs")) {
    $inputPath = Join-Path $FixtureDir $fixture
    $outPath = Join-Path $OutDir "$fixture.structure.json"
    pwsh (Join-Path $RepoRoot "tests\export-structure.ps1") `
        -InputPath $inputPath `
        -OutPath $outPath `
        -Container $Container
}

$cxiPath = Join-Path $FixtureDir "synthetic.cxi"
$runId = [Guid]::NewGuid().ToString("N")
$containerWork = "/tmp/ctr-cxi-fixture-$runId"
$headlessLog = Join-Path $OutDir "synthetic.cxi.headless.log"

try {
    docker exec $Container bash -lc "rm -rf $containerWork && mkdir -p $containerWork/input $containerWork/proj $containerWork/scripts" | Out-Null
    docker cp (Join-Path $RepoRoot "tests\ImportCxiCodeSetFixture.java") "${Container}:$containerWork/scripts/" | Out-Null
    docker cp $cxiPath "${Container}:$containerWork/input/synthetic.cxi" | Out-Null

    $raw = docker exec $Container bash -lc "/opt/ghidra/support/analyzeHeadless $containerWork/proj synthetic-cxi -scriptPath $containerWork/scripts -preScript ImportCxiCodeSetFixture.java $containerWork/input/synthetic.cxi -deleteProject" 2>&1
    $raw | Out-File -FilePath $headlessLog -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw "synthetic CXI code-set import failed; see $headlessLog"
    }

    foreach ($expected in @(
        "Mapped .text at 0x100000 size 0x4",
        "Mapped .rodata at 0x101000 size 0x4",
        "Mapped .data at 0x102000 size 0x4",
        "Mapped .bss at 0x102004 size 0x20",
        "Wrote 3DS ExHeader metadata"
    )) {
        if (@($raw | Select-String -SimpleMatch $expected).Count -eq 0) {
            throw "synthetic CXI log did not contain '$expected'; see $headlessLog"
        }
    }
}
finally {
    docker exec $Container bash -lc "rm -rf $containerWork" 2>$null | Out-Null
}

Write-Host "Generated fixture smoke tests passed"
