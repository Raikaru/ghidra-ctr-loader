# SPDX-License-Identifier: MIT
#
# Summarize warnings/errors from a headless Ghidra log without exposing program
# bytes or decompiled output.
#
# Usage:
#   pwsh tests/summarize-headless-log.ps1 -LogPath ".local-test\structure-export\run.headless.log"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $LogPath,

    [Parameter(Mandatory=$false)]
    [string] $OutPath = "",

    [Parameter(Mandatory=$false)]
    [int] $ExamplesPerKind = 5
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $LogPath)) {
    throw "Log path not found: $LogPath"
}

if ([string]::IsNullOrWhiteSpace($OutPath)) {
    $OutPath = [IO.Path]::ChangeExtension($LogPath, ".summary.json")
}

$entries = New-Object System.Collections.Generic.List[object]
foreach ($line in Get-Content -LiteralPath $LogPath) {
    if ($line -notmatch '^(WARN|ERROR)\s+(.+?)\s+\(([^)]+)\)\s*$') {
        continue
    }

    $level = $Matches[1]
    $message = $Matches[2]
    $source = $Matches[3]
    $kind = $message
    $kind = $kind -replace '0x[0-9a-fA-F]+', '0xADDR'
    $kind = $kind -replace '\b[0-9a-fA-F]{6,8}\b', 'ADDR'
    $kind = $kind -replace '\s+', ' '

    $entries.Add([pscustomobject]@{
        level = $level
        source = $source
        kind = $kind
        example = $message
    }) | Out-Null
}

$groups = @($entries | Group-Object level, source, kind | Sort-Object Count -Descending | ForEach-Object {
    $first = $_.Group | Select-Object -First $ExamplesPerKind
    [pscustomobject]@{
        count = $_.Count
        level = $first[0].level
        source = $first[0].source
        kind = $first[0].kind
        examples = @($first | ForEach-Object { $_.example })
    }
})

$summary = [pscustomobject]@{
    log_name = [IO.Path]::GetFileName($LogPath)
    warnings = @($entries | Where-Object level -eq "WARN").Count
    errors = @($entries | Where-Object level -eq "ERROR").Count
    groups = $groups
}

$summary | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutPath -Encoding utf8
Write-Host "Wrote $OutPath"
