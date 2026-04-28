# SPDX-License-Identifier: MIT
#
# Export a payload-free structural JSON summary for a local private 3DS
# executable/module import. The JSON must not contain game payload.
#
# Usage:
#   pwsh tests/export-structure.ps1 -InputPath "C:\path\decrypted.cxi"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $InputPath,

    [Parameter(Mandatory=$false)]
    [string] $OutPath = "",

    [Parameter(Mandatory=$false)]
    [string] $OutDir = "",

    [Parameter(Mandatory=$false)]
    [string] $ImportExtension = "",

    [Parameter(Mandatory=$false)]
    [string] $Processor = "",

    [Parameter(Mandatory=$false)]
    [string] $Compiler = "",

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
    $OutDir = Join-Path $RepoRoot ".local-test\structure-export"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if ([string]::IsNullOrWhiteSpace($OutPath)) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($InputPath) -replace '[^A-Za-z0-9_.-]', '_'
    $OutPath = Join-Path $OutDir "$stem.structure.json"
}

$safeStem = [IO.Path]::GetFileNameWithoutExtension($OutPath) -replace '[^A-Za-z0-9_.-]', '_'
$runId = [Guid]::NewGuid().ToString("N")
$containerWork = "/tmp/ctr-structure-$runId"
$headlessLog = Join-Path $OutDir "$safeStem.headless.log"

try {
    docker exec $Container bash -lc "rm -rf $containerWork && mkdir -p $containerWork/scripts $containerWork/input $containerWork/proj" | Out-Null
    docker cp (Join-Path $RepoRoot "tests\ExportCtrStructureJson.java") "${Container}:$containerWork/scripts/" | Out-Null
    $extension = [IO.Path]::GetExtension($InputPath)
    if (-not [string]::IsNullOrWhiteSpace($ImportExtension)) {
        $extension = $ImportExtension
        if (-not $extension.StartsWith(".")) {
            $extension = ".$extension"
        }
    }
    $inputName = "input$extension"
    if ([string]::IsNullOrWhiteSpace($extension)) {
        $inputName = "input.bin"
    }
    docker cp $InputPath "${Container}:$containerWork/input/$inputName" | Out-Null

    $importArgs = ""
    if (-not [string]::IsNullOrWhiteSpace($Processor)) {
        $importArgs += " -processor '$Processor'"
    }
    if (-not [string]::IsNullOrWhiteSpace($Compiler)) {
        $importArgs += " -cspec '$Compiler'"
    }

    $raw = docker exec $Container bash -lc "/opt/ghidra/support/analyzeHeadless $containerWork/proj export -import $containerWork/input/$inputName$importArgs -scriptPath $containerWork/scripts -postScript ExportCtrStructureJson.java -deleteProject" 2>&1
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
