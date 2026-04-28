# SPDX-License-Identifier: MIT
#
# Create a payload-safe quality report for a local 3DS decomp starter project.
#
# Usage:
#   pwsh tests/new-3ds-project-quality-report.ps1 `
#     -ProjectManifest ".local-test\decomp-projects\smt-iv\project.structure.json"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $ProjectManifest,

    [Parameter(Mandatory=$false)]
    [string] $OutPath = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $ProjectManifest)) {
    throw "Project manifest not found: $ProjectManifest"
}

function Read-JsonOrNull([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) {
        return $null
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Relative-Path([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }
    $repoRoot = Split-Path -Parent $PSScriptRoot
    try {
        return [IO.Path]::GetRelativePath($repoRoot, (Resolve-Path -LiteralPath $Path))
    } catch {
        return $Path
    }
}

$project = Read-JsonOrNull $ProjectManifest
$exefs = Read-JsonOrNull $project.exefs_manifest
$romfs = Read-JsonOrNull $project.romfs_manifest
$modules = Read-JsonOrNull $project.module_manifest
$validation = Read-JsonOrNull $project.module_validation

$projectRoot = Split-Path -Parent (Resolve-Path -LiteralPath $ProjectManifest)
if ([string]::IsNullOrWhiteSpace($OutPath)) {
    $OutPath = Join-Path $projectRoot "quality-report.structure.json"
} elseif (-not [IO.Path]::IsPathRooted($OutPath)) {
    $OutPath = Join-Path (Split-Path -Parent $PSScriptRoot) $OutPath
}
$markdownPath = [IO.Path]::ChangeExtension($OutPath, ".md")

$logPath = Join-Path (Split-Path -Parent $project.ghidra_project_dir) "$($project.project_name).container.headless.log"
$logSummaryPath = ""
$logSummary = $null
if (Test-Path $logPath) {
    $logSummaryPath = [IO.Path]::ChangeExtension($logPath, ".summary.json")
    & (Join-Path $PSScriptRoot "summarize-headless-log.ps1") -LogPath $logPath -OutPath $logSummaryPath | Out-Host
    $logSummary = Read-JsonOrNull $logSummaryPath
}

$topExtensions = @()
if ($null -ne $romfs -and $null -ne $romfs.extensions) {
    $topExtensions = @($romfs.extensions | Select-Object -First 12)
}

$serviceNames = @()
if ($null -ne $exefs -and $null -ne $exefs.service_access) {
    $serviceNames = @($exefs.service_access | ForEach-Object { $_.name } | Sort-Object -Unique)
}

$health = [ordered]@{
    has_code_set_manifest = ($null -ne $exefs)
    has_romfs_manifest = ($null -ne $romfs)
    has_module_manifest = ($null -ne $modules)
    ghidra_project_exists = (Test-Path $project.ghidra_project_dir)
    no_headless_errors = ($null -eq $logSummary -or $logSummary.errors -eq 0)
}

$report = [pscustomobject]@{
    project_name = $project.project_name
    source_name = $project.source_name
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    paths = [pscustomobject]@{
        project_manifest = Relative-Path $ProjectManifest
        ghidra_project_dir = Relative-Path $project.ghidra_project_dir
        exefs_manifest = Relative-Path $project.exefs_manifest
        romfs_manifest = Relative-Path $project.romfs_manifest
        module_manifest = Relative-Path $project.module_manifest
        headless_log_summary = Relative-Path $logSummaryPath
    }
    code_set = if ($null -eq $exefs) { $null } else { [pscustomobject]@{
        dependency_count = $exefs.dependency_count
        service_access_count = $exefs.service_access_count
        text = $exefs.code_set.text
        rodata = $exefs.code_set.rodata
        data = $exefs.code_set.data
        bss = $exefs.code_set.bss
        services = $serviceNames
    }}
    romfs = if ($null -eq $romfs) { $null } else { [pscustomobject]@{
        directory_count = $romfs.directory_count
        file_count = $romfs.file_count
        total_file_bytes = $romfs.total_file_bytes
        top_extensions = $topExtensions
    }}
    modules = if ($null -eq $modules) { $null } else { [pscustomobject]@{
        candidate_count = $modules.candidate_count
        cro_count = $modules.cro_count
        crs_count = $modules.crs_count
        validation_status = if ($null -eq $validation) { "" } else { $validation.status }
        validated_count = if ($null -eq $validation) { 0 } else { $validation.validated_count }
    }}
    headless = if ($null -eq $logSummary) { $null } else { [pscustomobject]@{
        warnings = $logSummary.warnings
        errors = $logSummary.errors
        top_groups = @($logSummary.groups | Select-Object -First 10)
    }}
    health = $health
}

$report | ConvertTo-Json -Depth 12 | Out-File -FilePath $OutPath -Encoding utf8

$headlessWarnings = if ($null -eq $report.headless) { "unknown" } else { $report.headless.warnings }
$headlessErrors = if ($null -eq $report.headless) { "unknown" } else { $report.headless.errors }
$moduleCandidates = if ($null -eq $report.modules) { "unknown" } else { $report.modules.candidate_count }
$moduleCro = if ($null -eq $report.modules) { "unknown" } else { $report.modules.cro_count }
$moduleCrs = if ($null -eq $report.modules) { "unknown" } else { $report.modules.crs_count }
$dependencyCount = if ($null -eq $report.code_set) { "unknown" } else { $report.code_set.dependency_count }
$serviceCount = if ($null -eq $report.code_set) { "unknown" } else { $report.code_set.service_access_count }

$md = New-Object System.Collections.Generic.List[string]
$md.Add("# 3DS Project Quality Report")
$md.Add("")
$md.Add("- Project: $($project.project_name)")
$md.Add("- Source: $($project.source_name)")
$md.Add("- Ghidra project: $($report.paths.ghidra_project_dir)")
$md.Add("- Headless warnings/errors: $headlessWarnings/$headlessErrors")
$md.Add("- Module candidates: $moduleCandidates CRO=$moduleCro CRS=$moduleCrs")
$md.Add("- Dependencies/services: $dependencyCount/$serviceCount")
$md.Add("")
$md.Add("## Health")
foreach ($item in $health.GetEnumerator()) {
    $md.Add("- $($item.Key): $($item.Value)")
}
$md.Add("")
$md.Add("## Top RomFS Extensions")
foreach ($ext in $topExtensions) {
    $md.Add("- $($ext.extension): $($ext.count)")
}
$md.Add("")
$md.Add("## Service Access")
if ($serviceNames.Count -eq 0) {
    $md.Add("- none recorded")
} else {
    foreach ($service in $serviceNames) {
        $md.Add("- $service")
    }
}
$md.Add("")
$md.Add("Payload rule: this report is structure-only; do not paste game content, decompiler output, raw bytes, decoded text, screenshots, audio, or assets into it.")
$md | Out-File -FilePath $markdownPath -Encoding utf8

Write-Host "Wrote $OutPath"
Write-Host "Wrote $markdownPath"
