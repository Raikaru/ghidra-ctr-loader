# SPDX-License-Identifier: MIT
#
# Compare two payload-free structure exports from ExportCtrStructureJson.java.
#
# Usage:
#   pwsh tests/compare-structure.ps1 -Baseline old.structure.json -Current new.structure.json

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $Baseline,

    [Parameter(Mandatory=$true)]
    [string] $Current
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $Baseline)) {
    throw "Baseline path not found: $Baseline"
}
if (-not (Test-Path $Current)) {
    throw "Current path not found: $Current"
}

$base = Get-Content $Baseline -Raw | ConvertFrom-Json
$next = Get-Content $Current -Raw | ConvertFrom-Json
$differences = New-Object System.Collections.Generic.List[string]

function Add-Difference([string] $Message) {
    $differences.Add($Message) | Out-Null
}

function Compare-Scalar([string] $Name, $BaseValue, $NextValue) {
    if ("$BaseValue" -ne "$NextValue") {
        Add-Difference "$Name changed: '$BaseValue' -> '$NextValue'"
    }
}

Compare-Scalar "language" $base.language $next.language
Compare-Scalar "compiler" $base.compiler $next.compiler
Compare-Scalar "image_base" $base.image_base $next.image_base

foreach ($name in @(
    "functions",
    "memory_blocks",
    "initialized_blocks",
    "uninitialized_blocks",
    "readable_blocks",
    "writable_blocks",
    "executable_blocks",
    "symbols_total",
    "external_libraries"
)) {
    Compare-Scalar "counts.$name" $base.counts.$name $next.counts.$name
}

$baseBlocks = @{}
foreach ($block in $base.memory_blocks) {
    $baseBlocks[$block.name] = $block
}

$nextBlocks = @{}
foreach ($block in $next.memory_blocks) {
    $nextBlocks[$block.name] = $block
}

foreach ($name in ($baseBlocks.Keys | Sort-Object)) {
    if (-not $nextBlocks.ContainsKey($name)) {
        Add-Difference "memory block removed: $name"
        continue
    }

    $a = $baseBlocks[$name]
    $b = $nextBlocks[$name]
    foreach ($field in @("start", "end", "type", "size", "read", "write", "execute")) {
        Compare-Scalar "memory_blocks.$name.$field" $a.$field $b.$field
    }
}

foreach ($name in ($nextBlocks.Keys | Sort-Object)) {
    if (-not $baseBlocks.ContainsKey($name)) {
        Add-Difference "memory block added: $name"
    }
}

$baseLibs = @($base.external_libraries | Sort-Object)
$nextLibs = @($next.external_libraries | Sort-Object)
Compare-Object -ReferenceObject $baseLibs -DifferenceObject $nextLibs | ForEach-Object {
    if ($_.SideIndicator -eq "<=") {
        Add-Difference "external library removed: $($_.InputObject)"
    } elseif ($_.SideIndicator -eq "=>") {
        Add-Difference "external library added: $($_.InputObject)"
    }
}

if ($differences.Count -eq 0) {
    Write-Host "Structure exports match"
    exit 0
}

$differences | ForEach-Object { Write-Host $_ }
exit 1
