# SPDX-License-Identifier: MIT
#
# Generate a payload-safe handoff markdown file for a 3DS decomp agent.
#
# Usage:
#   pwsh tests/new-3ds-decomp-handoff.ps1 `
#     -ProjectManifest ".local-test\decomp-projects\smt-iv\project.structure.json" `
#     -TargetName "SMT IV"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $ProjectManifest,

    [Parameter(Mandatory=$false)]
    [string] $QualityReport = "",

    [Parameter(Mandatory=$false)]
    [string] $TargetName = "",

    [Parameter(Mandatory=$false)]
    [string] $OutPath = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $ProjectManifest)) {
    throw "Project manifest not found: $ProjectManifest"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
function Rel([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return "" }
    try { return [IO.Path]::GetRelativePath($RepoRoot, (Resolve-Path -LiteralPath $Path)) } catch { return $Path }
}

$project = Get-Content -LiteralPath $ProjectManifest -Raw | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($TargetName)) {
    $TargetName = $project.project_name
}

if ([string]::IsNullOrWhiteSpace($QualityReport)) {
    $QualityReport = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $ProjectManifest)) "quality-report.structure.json"
    if (-not (Test-Path $QualityReport)) {
        & (Join-Path $PSScriptRoot "new-3ds-project-quality-report.ps1") -ProjectManifest $ProjectManifest -OutPath $QualityReport | Out-Host
    }
}
$quality = Get-Content -LiteralPath $QualityReport -Raw | ConvertFrom-Json

if ([string]::IsNullOrWhiteSpace($OutPath)) {
    $OutPath = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $ProjectManifest)) "handoff.md"
} elseif (-not [IO.Path]::IsPathRooted($OutPath)) {
    $OutPath = Join-Path $RepoRoot $OutPath
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# $TargetName 3DS Decomp Handoff")
$lines.Add("")
$lines.Add("Use this with legally obtained, user-owned local artifacts only. Keep ROMs, extracted binaries, decompiler output, decoded text, screenshots, audio, and raw byte ranges out of committed notes.")
$lines.Add("")
$lines.Add("## Local Project")
$lines.Add("")
$lines.Add("- Ghidra project: $(Rel $project.ghidra_project_dir)")
$lines.Add("- Project manifest: $(Rel $ProjectManifest)")
$lines.Add("- Quality report: $(Rel $QualityReport)")
$lines.Add("- ExeFS manifest: $(Rel $project.exefs_manifest)")
$lines.Add("- RomFS manifest: $(Rel $project.romfs_manifest)")
$lines.Add("- Module manifest: $(Rel $project.module_manifest)")
$lines.Add("")
$lines.Add("## Current Import Health")
$lines.Add("")
$headlessWarnings = if ($null -eq $quality.headless) { "unknown" } else { $quality.headless.warnings }
$headlessErrors = if ($null -eq $quality.headless) { "unknown" } else { $quality.headless.errors }
$dependencyCount = if ($null -eq $quality.code_set) { "unknown" } else { $quality.code_set.dependency_count }
$serviceCount = if ($null -eq $quality.code_set) { "unknown" } else { $quality.code_set.service_access_count }
$moduleCandidates = if ($null -eq $quality.modules) { "unknown" } else { $quality.modules.candidate_count }
$moduleCro = if ($null -eq $quality.modules) { "unknown" } else { $quality.modules.cro_count }
$moduleCrs = if ($null -eq $quality.modules) { "unknown" } else { $quality.modules.crs_count }
$lines.Add("- Headless warnings/errors: $headlessWarnings/$headlessErrors")
$lines.Add("- Dependency/service counts: $dependencyCount/$serviceCount")
$lines.Add("- Module candidates: $moduleCandidates total, $moduleCro CRO, $moduleCrs CRS")
$lines.Add("- Ghidra project exists: $($quality.health.ghidra_project_exists)")
$lines.Add("")
$lines.Add("## Suggested First Pass")
$lines.Add("")
$lines.Add("1. Open the mapped code-set project and confirm `ctr_entry`, `.text`, `.rodata`, `.data`, and `.bss` are present.")
$lines.Add("2. Use Program Info and external libraries to identify service-heavy areas first: FS, GSP, HID, RO, APT, DSP, and related service handles.")
$lines.Add("3. Prioritize wrapper naming before game logic: SVC wrappers, service IPC send paths, filesystem/archive open/read paths, allocator/thread/event/mutex helpers.")
$lines.Add("4. Identify the boot/init path, main loop, resource-loading layer, text/message loader, script VM entrypoints, and battle-state update path.")
$lines.Add("5. Record observations as hypotheses with confidence. Do not copy decompiler output into source or docs.")
$lines.Add("")
$lines.Add("## Payload-Safe Notes")
$lines.Add("")
$lines.Add("- Commit only source, docs, scripts, and structure summaries.")
$lines.Add("- Keep local observations generic: symbol names, addresses, counts, control-flow roles, and format hypotheses are okay; copied proprietary content is not.")
$lines.Add("- When creating reusable plugin improvements, move only generic loader/analyzer behavior back into this repo.")

$lines | Out-File -FilePath $OutPath -Encoding utf8
Write-Host "Wrote $OutPath"
