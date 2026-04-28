# SPDX-License-Identifier: MIT
#
# Extract NCCH partitions from a private decrypted NCSD/CCI/.3ds image into
# ignored local test space. Do not commit the output.
#
# Usage:
#   pwsh tests/extract-ncsd-partitions.ps1 -InputPath "C:\path\to\game.3ds"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $InputPath,

    [Parameter(Mandatory=$false)]
    [string] $OutDir = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $InputPath)) {
    throw "Input path not found: $InputPath"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($InputPath) -replace '[^A-Za-z0-9_.-]', '_'
    $OutDir = Join-Path $RepoRoot ".local-test\ncsd\$stem"
} elseif (-not [IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path $RepoRoot $OutDir
}
if (Test-Path $OutDir) {
    Remove-Item -Recurse -Force $OutDir
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$fs = [IO.File]::OpenRead($InputPath)
$br = [IO.BinaryReader]::new($fs)
try {
    $fs.Position = 0x100
    $magic = [Text.Encoding]::ASCII.GetString($br.ReadBytes(4))
    if ($magic -ne "NCSD") {
        throw "Expected NCSD magic at 0x100, got '$magic'"
    }

    $fs.Position = 0x140
    $partitions = @()
    $fs.Position = 0x120
    for ($i = 0; $i -lt 8; $i++) {
        $offsetMedia = $br.ReadUInt32()
        $lengthMedia = $br.ReadUInt32()
        if ($offsetMedia -eq 0 -or $lengthMedia -eq 0) {
            continue
        }

        $offset = [int64] $offsetMedia * 0x200L
        $length = [int64] $lengthMedia * 0x200L
        if ($offset -lt 0 -or $length -lt 0 -or ($offset + $length) -gt $fs.Length) {
            continue
        }

        $fs.Position = $offset + 0x100
        $partitionMagic = [Text.Encoding]::ASCII.GetString($br.ReadBytes(4))
        if ($partitionMagic -ne "NCCH") {
            continue
        }

        $fileName = "partition$i.$($partitionMagic.ToLowerInvariant())"
        $fileName = "partition$i.cxi"
        $outPath = Join-Path $OutDir $fileName

        $out = [IO.File]::Create($outPath)
        try {
            $fs.Position = $offset
            $remaining = $length
            $buffer = New-Object byte[] 1048576
            while ($remaining -gt 0) {
                $wanted = [int] [Math]::Min($buffer.Length, $remaining)
                $read = $fs.Read($buffer, 0, $wanted)
                if ($read -le 0) {
                    throw "Unexpected EOF while extracting partition $i"
                }
                $out.Write($buffer, 0, $read)
                $remaining -= $read
            }
        } finally {
            $out.Dispose()
        }

        $partitions += [pscustomobject]@{
            index = $i
            magic = $partitionMagic
            offset = ("0x{0:x}" -f $offset)
            size = $length
            file = $fileName
        }
    }

    $manifest = [pscustomobject]@{
        source_name = [IO.Path]::GetFileName($InputPath)
        partition_count = $partitions.Count
        partitions = $partitions
    }
    $manifestPath = Join-Path $OutDir "manifest.structure.json"
    $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestPath -Encoding utf8
    Write-Host "Wrote NCSD partitions to $OutDir"
    Write-Host "Wrote $manifestPath"
} finally {
    $br.Dispose()
    $fs.Dispose()
}
