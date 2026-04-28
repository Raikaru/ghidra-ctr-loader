# SPDX-License-Identifier: MIT
#
# Create a persistent local Ghidra project directly from a decrypted CXI/CIA by
# importing its /exefs/code.bin member through the code-set loader.
#
# Usage:
#   pwsh tests/create-container-code-set-project.ps1 `
#     -InputPath "C:\path\to\decrypted.cxi" `
#     -ProjectName "game-code-set"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $InputPath,

    [Parameter(Mandatory=$false)]
    [string] $ProjectName = "",

    [Parameter(Mandatory=$false)]
    [string] $OutDir = "",

    [Parameter(Mandatory=$false)]
    [string] $Container = "ghidra-mcp"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $InputPath)) {
    throw "Input path not found: $InputPath"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RepoRoot ".local-test\ghidra-projects"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if ([string]::IsNullOrWhiteSpace($ProjectName)) {
    $ProjectName = [IO.Path]::GetFileNameWithoutExtension($InputPath)
}
$ProjectName = $ProjectName -replace '[^A-Za-z0-9_.-]', '_'
if ($ProjectName -notmatch '[A-Za-z0-9]' -or $ProjectName -eq "." -or $ProjectName -eq "..") {
    $ProjectName = "ctr-container-code-set"
}

$runId = [Guid]::NewGuid().ToString("N")
$containerWork = "/tmp/ctr-container-project-$runId"
$containerProjectRoot = "$containerWork/proj"
$localProjectDir = Join-Path $OutDir $ProjectName
$headlessLog = Join-Path $OutDir "$ProjectName.container.headless.log"
$extension = [IO.Path]::GetExtension($InputPath)
if ([string]::IsNullOrWhiteSpace($extension)) {
    $extension = ".cxi"
}
$magicFs = [IO.File]::OpenRead($InputPath)
try {
    $magicFs.Position = 0x100
    $magicBytes = New-Object byte[] 4
    if ($magicFs.Read($magicBytes, 0, 4) -eq 4) {
        $magic = [Text.Encoding]::ASCII.GetString($magicBytes)
        if ($magic -eq "NCCH") {
            $extension = ".cxi"
        } elseif ($magic -eq "NCSD") {
            $extension = ".3ds"
        }
    }
} finally {
    $magicFs.Dispose()
}

if (Test-Path $localProjectDir) {
    Remove-Item -Recurse -Force $localProjectDir
}

try {
    docker exec $Container bash -lc "rm -rf $containerWork && mkdir -p $containerWork/scripts $containerWork/input $containerProjectRoot" | Out-Null
    docker cp (Join-Path $RepoRoot "tests\ImportCxiCodeSetFixture.java") "${Container}:$containerWork/scripts/" | Out-Null
    docker cp $InputPath "${Container}:$containerWork/input/input$extension" | Out-Null

    $raw = docker exec $Container bash -lc "/opt/ghidra/support/analyzeHeadless $containerProjectRoot $ProjectName -scriptPath $containerWork/scripts -preScript ImportCxiCodeSetFixture.java $containerWork/input/input$extension" 2>&1
    $raw | Out-File -FilePath $headlessLog -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw "analyzeHeadless failed; see $headlessLog"
    }
    if ($raw | Select-String -Pattern 'REPORT SCRIPT ERROR|error: cannot find symbol|skipping .+\.java') {
        throw "analyzeHeadless reported a script error; see $headlessLog"
    }

    New-Item -ItemType Directory -Force -Path $localProjectDir | Out-Null
    docker cp "${Container}:$containerProjectRoot/." $localProjectDir | Out-Null
    Write-Host "Wrote project to $localProjectDir"
    Write-Host "Wrote $headlessLog"
}
finally {
    docker exec $Container bash -lc "rm -rf $containerWork" 2>$null | Out-Null
}
