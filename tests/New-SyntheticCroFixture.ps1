# SPDX-License-Identifier: MIT
#
# Generate tiny synthetic CRO/CRS files for loader smoke tests. The fixtures
# contain only invented bytes and metadata, never game payload.
#
# Usage:
#   pwsh tests/New-SyntheticCroFixture.ps1 -OutDir .local-test/generated

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string] $OutDir = ".local-test\generated"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not [IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path $RepoRoot $OutDir
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Write-Int32Le([IO.BinaryWriter] $Writer, [int] $Value) {
    $Writer.Write([BitConverter]::GetBytes($Value))
}

function Write-Int64Le([IO.BinaryWriter] $Writer, [long] $Value) {
    $Writer.Write([BitConverter]::GetBytes($Value))
}

function Write-AsciiZ([IO.BinaryWriter] $Writer, [string] $Value) {
    $Writer.Write([Text.Encoding]::ASCII.GetBytes($Value))
    $Writer.Write([byte] 0)
}

function Pad-To([IO.BinaryWriter] $Writer, [int] $Offset) {
    while ($Writer.BaseStream.Position -lt $Offset) {
        $Writer.Write([byte] 0)
    }
    if ($Writer.BaseStream.Position -ne $Offset) {
        throw "Fixture writer passed target offset 0x$($Offset.ToString('x'))"
    }
}

function New-CroBytes {
    $headerSize = 0x138
    $moduleNameOffset = 0x138
    $segmentTableOffset = 0x148
    $namedExportTableOffset = 0x178
    $exportStringsOffset = 0x180
    $dataOffset = 0x190
    $textOffset = $dataOffset
    $rodataOffset = $textOffset + 4
    $dataSegmentOffset = $rodataOffset + 4
    $fileSize = $dataSegmentOffset + 4
    $bssSize = 0x20

    $stream = New-Object IO.MemoryStream
    $writer = New-Object IO.BinaryWriter($stream)

    $writer.Write((New-Object byte[] 0x80))
    $writer.Write([Text.Encoding]::ASCII.GetBytes("CRO0"))
    Write-Int32Le $writer $moduleNameOffset
    Write-Int32Le $writer -1
    Write-Int32Le $writer -1
    Write-Int32Le $writer $fileSize
    Write-Int32Le $writer $bssSize
    Write-Int64Le $writer 0
    Write-Int32Le $writer 0
    Write-Int32Le $writer -1
    Write-Int32Le $writer -1
    Write-Int32Le $writer -1
    Write-Int32Le $writer $textOffset
    Write-Int32Le $writer 4
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 12
    Write-Int32Le $writer $moduleNameOffset
    Write-Int32Le $writer 10
    Write-Int32Le $writer $segmentTableOffset
    Write-Int32Le $writer 4
    Write-Int32Le $writer $namedExportTableOffset
    Write-Int32Le $writer 1
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 0
    Write-Int32Le $writer $exportStringsOffset
    Write-Int32Le $writer 16
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 0
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 0
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 0
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 0
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 0
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 0
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 0
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 0
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 0
    Write-Int32Le $writer $dataOffset
    Write-Int32Le $writer 0

    if ($writer.BaseStream.Position -ne $headerSize) {
        throw "Synthetic CRO header size mismatch: $($writer.BaseStream.Position)"
    }

    Write-AsciiZ $writer "synthetic"
    Pad-To $writer $segmentTableOffset

    foreach ($entry in @(
        @($textOffset, 4, 0),
        @($rodataOffset, 4, 1),
        @($dataSegmentOffset, 4, 2),
        @(0, $bssSize, 3)
    )) {
        Write-Int32Le $writer $entry[0]
        Write-Int32Le $writer $entry[1]
        Write-Int32Le $writer $entry[2]
    }

    Pad-To $writer $namedExportTableOffset
    Write-Int32Le $writer $exportStringsOffset
    Write-Int32Le $writer 0

    Pad-To $writer $exportStringsOffset
    Write-AsciiZ $writer "synthetic_entry"

    Pad-To $writer $dataOffset
    $writer.Write([byte[]] @(0x1e, 0xff, 0x2f, 0xe1))
    $writer.Write([byte[]] @(0x78, 0x56, 0x34, 0x12))
    $writer.Write([byte[]] @(0x00, 0x00, 0x00, 0x00))

    if ($writer.BaseStream.Position -ne $fileSize) {
        throw "Synthetic CRO file size mismatch: $($writer.BaseStream.Position)"
    }

    $bytes = $stream.ToArray()
    $writer.Dispose()
    $stream.Dispose()
    return $bytes
}

$bytes = New-CroBytes
$croPath = Join-Path $OutDir "synthetic.cro"
$crsPath = Join-Path $OutDir "synthetic.crs"
[IO.File]::WriteAllBytes($croPath, $bytes)
[IO.File]::WriteAllBytes($crsPath, $bytes)

Write-Host "Wrote $croPath"
Write-Host "Wrote $crsPath"
