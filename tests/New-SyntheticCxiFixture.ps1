# SPDX-License-Identifier: MIT
#
# Generate a tiny payload-free CXI/NCCH fixture with an ExeFS .code member.
# The bytes are synthetic and only exercise the loader's code-set mapping path.

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string] $OutDir = ".local-test\generated"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outPath = Join-Path $OutDir "synthetic.cxi"

$fileSize = 0x4000
$bytes = New-Object byte[] $fileSize

function Write-Bytes {
    param(
        [Parameter(Mandatory=$true)]
        [byte[]] $Buffer,
        [Parameter(Mandatory=$true)]
        [int] $Offset,
        [Parameter(Mandatory=$true)]
        [byte[]] $Data
    )
    [Array]::Copy($Data, 0, $Buffer, $Offset, $Data.Length)
}

function Write-AsciiFixed {
    param(
        [Parameter(Mandatory=$true)]
        [byte[]] $Buffer,
        [Parameter(Mandatory=$true)]
        [int] $Offset,
        [Parameter(Mandatory=$true)]
        [int] $Length,
        [Parameter(Mandatory=$true)]
        [string] $Value
    )
    $data = [Text.Encoding]::ASCII.GetBytes($Value)
    [Array]::Copy($data, 0, $Buffer, $Offset, [Math]::Min($Length, $data.Length))
}

function Write-U16 {
    param([byte[]] $Buffer, [int] $Offset, [UInt16] $Value)
    Write-Bytes $Buffer $Offset ([BitConverter]::GetBytes($Value))
}

function Write-U32 {
    param([byte[]] $Buffer, [int] $Offset, [UInt32] $Value)
    Write-Bytes $Buffer $Offset ([BitConverter]::GetBytes($Value))
}

function Write-U64 {
    param([byte[]] $Buffer, [int] $Offset, [UInt64] $Value)
    Write-Bytes $Buffer $Offset ([BitConverter]::GetBytes($Value))
}

function Convert-HexU32 {
    param([Parameter(Mandatory=$true)] [string] $Value)
    return [UInt32]::Parse($Value, [Globalization.NumberStyles]::AllowHexSpecifier)
}

# NCCH header.
Write-U32 $bytes 0x100 0x4843434e # "NCCH" as read little-endian.
Write-U32 $bytes 0x104 ([UInt32]($fileSize / 0x200))
Write-U64 $bytes 0x108 0x000400000ff40ff4
Write-U16 $bytes 0x110 0x3030
Write-U16 $bytes 0x112 0x0001
Write-U64 $bytes 0x118 0x000400000ff40ff4
Write-AsciiFixed $bytes 0x150 16 "SYNTH-CODESET"
Write-U32 $bytes 0x180 0x00000800 # ExHeader size.
Write-U32 $bytes 0x1a0 0x00000008 # ExeFS offset in media units.
Write-U32 $bytes 0x1a4 0x00000012 # ExeFS size in media units.
Write-U32 $bytes 0x1a8 0x00000002 # ExeFS hash size.

# NCCH ExHeader SystemControlInfo code-set layout.
Write-AsciiFixed $bytes 0x200 8 "SYNTH"
Write-U32 $bytes 0x210 0x00100000 # .text address.
Write-U32 $bytes 0x214 0x00000001 # .text physical pages.
Write-U32 $bytes 0x218 0x00000004 # .text size.
Write-U32 $bytes 0x21c 0x00004000 # Stack size.
Write-U32 $bytes 0x220 0x00101000 # .rodata address.
Write-U32 $bytes 0x224 0x00000001 # .rodata physical pages.
Write-U32 $bytes 0x228 0x00000004 # .rodata size.
Write-U32 $bytes 0x230 0x00102000 # .data address.
Write-U32 $bytes 0x234 0x00000001 # .data physical pages.
Write-U32 $bytes 0x238 0x00000004 # .data size.
Write-U32 $bytes 0x23c 0x00000020 # .bss size.
Write-U64 $bytes 0x240 0x0004013000001702 # Synthetic dependency ID.

# ExeFS header and .code payload. File data starts at ExeFS + 0x200.
$exefsStart = 0x1000
Write-AsciiFixed $bytes $exefsStart 8 ".code"
Write-U32 $bytes ($exefsStart + 0x08) 0x00000000
Write-U32 $bytes ($exefsStart + 0x0c) 0x00002004

$codeStart = $exefsStart + 0x200
Write-U32 $bytes ($codeStart + 0x0000) (Convert-HexU32 "e12fff1e") # bx lr
Write-U32 $bytes ($codeStart + 0x1000) 0x12345678
Write-U32 $bytes ($codeStart + 0x2000) (Convert-HexU32 "89abcdef")

[IO.File]::WriteAllBytes($outPath, $bytes)
Write-Host "Wrote $outPath"
