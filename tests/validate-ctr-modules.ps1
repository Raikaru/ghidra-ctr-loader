# SPDX-License-Identifier: MIT
#
# Validate CRO/CRS candidates from a payload-safe module manifest. Extracted
# private modules and headless logs stay under ignored .local-test output.
#
# Usage:
#   pwsh tests/validate-ctr-modules.ps1 `
#     -InputPath "C:\path\to\decrypted.cxi" `
#     -ModuleManifest ".local-test\decomp-projects\game\modules\game.modules.structure.json" `
#     -ExtractedExeFsDir ".local-test\decomp-projects\game\exefs"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $InputPath,

    [Parameter(Mandatory=$true)]
    [string] $ModuleManifest,

    [Parameter(Mandatory=$false)]
    [int] $Limit = 5,

    [Parameter(Mandatory=$false)]
    [string] $OutDir = "",

    [Parameter(Mandatory=$false)]
    [string] $ExtractedExeFsDir = "",

    [Parameter(Mandatory=$false)]
    [string] $Container = "ghidra-mcp"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $InputPath)) {
    throw "Input path not found: $InputPath"
}
if (-not (Test-Path $ModuleManifest)) {
    throw "Module manifest not found: $ModuleManifest"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($InputPath) -replace '[^A-Za-z0-9_.-]', '_'
    $OutDir = Join-Path $RepoRoot ".local-test\module-validation\$stem"
} elseif (-not [IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path $RepoRoot $OutDir
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Safe-Name([string] $Value) {
    return (($Value.TrimStart("/") -replace '[\\/]+', "__") -replace '[^A-Za-z0-9_.-]', '_')
}

$manifest = Get-Content -LiteralPath $ModuleManifest -Raw | ConvertFrom-Json
$candidates = @($manifest.candidates | Select-Object -First $Limit)
$validated = New-Object System.Collections.Generic.List[object]

if ($candidates.Count -eq 0) {
    $summary = [pscustomobject]@{
        source_name = [IO.Path]::GetFileName($InputPath)
        module_manifest = [IO.Path]::GetFileName($ModuleManifest)
        candidate_count = 0
        validated_count = 0
        status = "no_modules_found"
        modules = @()
    }
    $summaryPath = Join-Path $OutDir "validation.structure.json"
    $summary | ConvertTo-Json -Depth 8 | Out-File -FilePath $summaryPath -Encoding utf8
    Write-Host "Wrote $summaryPath"
    return
}

$moduleManifestDir = Split-Path -Parent (Resolve-Path -LiteralPath $ModuleManifest)
if (-not [string]::IsNullOrWhiteSpace($ExtractedExeFsDir)) {
    if (-not [IO.Path]::IsPathRooted($ExtractedExeFsDir)) {
        $ExtractedExeFsDir = Join-Path $RepoRoot $ExtractedExeFsDir
    }
    if (-not (Test-Path $ExtractedExeFsDir)) {
        throw "Extracted ExeFS directory not found: $ExtractedExeFsDir"
    }
}
$moduleInputDir = Join-Path $OutDir "inputs"
$moduleStructureDir = Join-Path $OutDir "structure"
New-Item -ItemType Directory -Force -Path $moduleInputDir, $moduleStructureDir | Out-Null

foreach ($candidate in $candidates) {
    $safe = Safe-Name $candidate.path
    $inputModulePath = Join-Path $moduleInputDir $safe

    if ($candidate.source -eq "romfs") {
        & (Join-Path $PSScriptRoot "extract-cxi-romfs-file.ps1") `
            -InputPath $InputPath `
            -RomFsPath $candidate.path `
            -OutPath $inputModulePath | Out-Host
    } elseif ($candidate.source -eq "exefs") {
        $name = [IO.Path]::GetFileName($candidate.path) -replace '[^A-Za-z0-9_.-]', '_'
        $candidateDirs = @()
        if (-not [string]::IsNullOrWhiteSpace($ExtractedExeFsDir)) {
            $candidateDirs += $ExtractedExeFsDir
        }
        $candidateDirs += $moduleManifestDir
        $candidateDirs += (Join-Path (Split-Path -Parent $moduleManifestDir) "exefs")
        $sourcePath = $null
        foreach ($dir in $candidateDirs) {
            $path = Join-Path $dir $name
            if (Test-Path $path) {
                $sourcePath = $path
                break
            }
        }
        if ($null -eq $sourcePath) {
            throw "ExeFS module candidate is not extracted; pass -ExtractedExeFsDir for $($candidate.path)"
        }
        Copy-Item -LiteralPath $sourcePath -Destination $inputModulePath -Force
    } else {
        throw "Unsupported module source '$($candidate.source)' for $($candidate.path)"
    }

    $structurePath = Join-Path $moduleStructureDir "$safe.structure.json"
    & (Join-Path $PSScriptRoot "export-structure.ps1") `
        -InputPath $inputModulePath `
        -OutPath $structurePath `
        -ImportExtension $candidate.extension `
        -Container $Container | Out-Host

    $structure = Get-Content -LiteralPath $structurePath -Raw | ConvertFrom-Json
    $validated.Add([pscustomobject]@{
        source = $candidate.source
        path = $candidate.path
        extension = $candidate.extension
        size = $candidate.size
        structure_file = [IO.Path]::GetFileName($structurePath)
        block_count = @($structure.blocks).Count
        symbol_count = $structure.symbol_count
        function_count = $structure.function_count
    }) | Out-Null
}

$summary = [pscustomobject]@{
    source_name = [IO.Path]::GetFileName($InputPath)
    module_manifest = [IO.Path]::GetFileName($ModuleManifest)
    candidate_count = $manifest.candidate_count
    validated_count = $validated.Count
    status = "validated"
    modules = @($validated)
}
$summaryPath = Join-Path $OutDir "validation.structure.json"
$summary | ConvertTo-Json -Depth 8 | Out-File -FilePath $summaryPath -Encoding utf8
Write-Host "Wrote $summaryPath"
