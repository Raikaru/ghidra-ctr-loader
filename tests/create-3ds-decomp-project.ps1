# SPDX-License-Identifier: MIT
#
# Build the local payload-safe starter artifacts for a 3DS decomp project:
# NCSD partition extraction when needed, ExeFS extraction, RomFS listing,
# CRO/CRS discovery, and a persistent Ghidra code-set project.
#
# Usage:
#   pwsh tests/create-3ds-decomp-project.ps1 `
#     -InputPath "C:\path\to\decrypted.3ds" `
#     -ProjectName "game-code-set"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $InputPath,

    [Parameter(Mandatory=$true)]
    [string] $ProjectName,

    [Parameter(Mandatory=$false)]
    [string] $OutDir = "",

    [Parameter(Mandatory=$false)]
    [string] $Container = "ghidra-mcp",

    [Parameter(Mandatory=$false)]
    [switch] $ValidateModules
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $InputPath)) {
    throw "Input path not found: $InputPath"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RepoRoot ".local-test\decomp-projects"
} elseif (-not [IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path $RepoRoot $OutDir
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$safeProjectName = $ProjectName -replace '[^A-Za-z0-9_.-]', '_'
if ($safeProjectName -notmatch '[A-Za-z0-9]' -or $safeProjectName -eq "." -or $safeProjectName -eq "..") {
    throw "ProjectName must contain at least one safe alphanumeric character"
}

function Read-Magic([string] $Path) {
    $fs = [IO.File]::OpenRead($Path)
    try {
        $fs.Position = 0x100
        $bytes = New-Object byte[] 4
        $read = $fs.Read($bytes, 0, 4)
        if ($read -ne 4) {
            throw "Could not read container magic from $Path"
        }
        return [Text.Encoding]::ASCII.GetString($bytes)
    } finally {
        $fs.Dispose()
    }
}

$workingInput = Resolve-Path -LiteralPath $InputPath
$ncsdManifestPath = ""
$magic = Read-Magic $workingInput
if ($magic -eq "NCSD") {
    $ncsdOut = Join-Path $OutDir "$safeProjectName\ncsd"
    & (Join-Path $PSScriptRoot "extract-ncsd-partitions.ps1") -InputPath $workingInput -OutDir $ncsdOut | Out-Host
    $ncsdManifestPath = Join-Path $ncsdOut "manifest.structure.json"
    $ncsdManifest = Get-Content -LiteralPath $ncsdManifestPath -Raw | ConvertFrom-Json
    $firstPartition = @($ncsdManifest.partitions | Sort-Object index | Select-Object -First 1)[0]
    if ($null -eq $firstPartition) {
        throw "NCSD container had no NCCH partitions"
    }
    $workingInput = Join-Path $ncsdOut $firstPartition.file
    $magic = Read-Magic $workingInput
}

if ($magic -ne "NCCH") {
    throw "Expected an NCCH/CXI input or NCSD/CCI/.3ds with an NCCH partition, got magic '$magic'"
}

$projectRoot = Join-Path $OutDir $safeProjectName
$exefsDir = Join-Path $projectRoot "exefs"
$romfsListDir = Join-Path $projectRoot "romfs-list"
$moduleDir = Join-Path $projectRoot "modules"
$ghidraDir = Join-Path $projectRoot "ghidra"
New-Item -ItemType Directory -Force -Path $projectRoot, $romfsListDir, $moduleDir, $ghidraDir | Out-Null

& (Join-Path $PSScriptRoot "extract-cxi-exefs.ps1") -InputPath $workingInput -OutDir $exefsDir | Out-Host
$exefsManifest = Join-Path $exefsDir "manifest.structure.json"

$romfsManifest = Join-Path $romfsListDir "$safeProjectName.romfs.structure.json"
try {
    & (Join-Path $PSScriptRoot "list-cxi-romfs.ps1") -InputPath $workingInput -OutPath $romfsManifest | Out-Host
} catch {
    if ($_.Exception.Message -notmatch "No RomFS region found") {
        throw
    }
    $emptyRomFs = [pscustomobject]@{
        source_name = [IO.Path]::GetFileName($workingInput)
        romfs_offset = "0x0"
        romfs_size = "0x0"
        level3_length = 0
        directory_count = 0
        file_count = 0
        total_file_bytes = 0
        extensions = @()
        directories = @()
        files = @()
    }
    $emptyRomFs | ConvertTo-Json -Depth 6 | Out-File -FilePath $romfsManifest -Encoding utf8
    Write-Host "Wrote empty RomFS manifest to $romfsManifest"
}

$moduleManifest = Join-Path $moduleDir "$safeProjectName.modules.structure.json"
& (Join-Path $PSScriptRoot "find-ctr-modules.ps1") `
    -ExeFsManifest $exefsManifest `
    -RomFsManifest $romfsManifest `
    -OutPath $moduleManifest | Out-Host

$ghidraProjectOut = Join-Path $ghidraDir "projects"
& (Join-Path $PSScriptRoot "create-container-code-set-project.ps1") `
    -InputPath $workingInput `
    -ProjectName $safeProjectName `
    -OutDir $ghidraProjectOut `
    -Container $Container | Out-Host

$moduleValidation = ""
$moduleDiscovery = Get-Content -LiteralPath $moduleManifest -Raw | ConvertFrom-Json
if ($ValidateModules -and $moduleDiscovery.candidate_count -gt 0) {
    $moduleValidationDir = Join-Path $moduleDir "validation"
    & (Join-Path $PSScriptRoot "validate-ctr-modules.ps1") `
        -InputPath $workingInput `
        -ModuleManifest $moduleManifest `
        -OutDir $moduleValidationDir `
        -Container $Container | Out-Host
    $moduleValidation = Join-Path $moduleValidationDir "validation.structure.json"
}

$summary = [pscustomobject]@{
    project_name = $safeProjectName
    source_name = [IO.Path]::GetFileName($InputPath)
    working_container = [IO.Path]::GetFileName($workingInput)
    ncsd_manifest = $ncsdManifestPath
    exefs_manifest = $exefsManifest
    romfs_manifest = $romfsManifest
    module_manifest = $moduleManifest
    module_validation = $moduleValidation
    ghidra_project_dir = Join-Path $ghidraProjectOut $safeProjectName
    module_candidate_count = $moduleDiscovery.candidate_count
    cro_count = $moduleDiscovery.cro_count
    crs_count = $moduleDiscovery.crs_count
}

$summaryPath = Join-Path $projectRoot "project.structure.json"
$summary | ConvertTo-Json -Depth 6 | Out-File -FilePath $summaryPath -Encoding utf8
Write-Host "Wrote $summaryPath"
