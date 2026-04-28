# SPDX-License-Identifier: MIT
#
# Wrap the synthetic CXI fixture in a minimal decrypted CIA container that is
# just rich enough to exercise the CIA filesystem offset path. It contains no
# game payload.

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

$cxiPath = Join-Path $OutDir "synthetic.cxi"
if (-not (Test-Path $cxiPath)) {
    pwsh (Join-Path $RepoRoot "tests\New-SyntheticCxiFixture.ps1") -OutDir $OutDir
}

$outPath = Join-Path $OutDir "synthetic.cia"
$cxi = [IO.File]::ReadAllBytes($cxiPath)

function Write-U16Le([IO.BinaryWriter] $Writer, [UInt16] $Value) { [void] $Writer.Write([BitConverter]::GetBytes($Value)) }
function Write-U32Le([IO.BinaryWriter] $Writer, [UInt32] $Value) { [void] $Writer.Write([BitConverter]::GetBytes($Value)) }
function Write-U64Le([IO.BinaryWriter] $Writer, [UInt64] $Value) { [void] $Writer.Write([BitConverter]::GetBytes($Value)) }

function Write-U16Be([IO.BinaryWriter] $Writer, [UInt16] $Value) {
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    [void] $Writer.Write($bytes)
}
function Write-U32Be([IO.BinaryWriter] $Writer, [UInt32] $Value) {
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    [void] $Writer.Write($bytes)
}
function Write-U64Be([IO.BinaryWriter] $Writer, [UInt64] $Value) {
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    [void] $Writer.Write($bytes)
}
function Pad-ToAlign([IO.BinaryWriter] $Writer, [int] $Align) {
    while (($Writer.BaseStream.Position % $Align) -ne 0) {
        [void] $Writer.Write([byte] 0)
    }
}
function Write-Zeros([IO.BinaryWriter] $Writer, [int] $Count) {
    if ($Count -gt 0) {
        [void] $Writer.Write((New-Object byte[] $Count))
    }
}
function Convert-HexU32([string] $Value) {
    return [UInt32]::Parse($Value, [Globalization.NumberStyles]::AllowHexSpecifier)
}
function Convert-HexU64([string] $Value) {
    return [UInt64]::Parse($Value, [Globalization.NumberStyles]::AllowHexSpecifier)
}
function Write-HexBytes([IO.BinaryWriter] $Writer, [string] $Hex) {
    for ($i = 0; $i -lt $Hex.Length; $i += 2) {
        [void] $Writer.Write([byte] [Convert]::ToByte($Hex.Substring($i, 2), 16))
    }
}
function New-CertificateBytes {
    $stream = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new($stream)
    Write-HexBytes $writer "00010002"
    Write-Zeros $writer 0x3c
    Write-Zeros $writer 0x40
    Write-Zeros $writer 0x40
    Write-HexBytes $writer "00000002"
    Write-Zeros $writer 0x40
    Write-HexBytes $writer "00000000"
    Write-Zeros $writer 0x3c
    Write-Zeros $writer 0x3c
    $bytes = $stream.ToArray()
    $writer.Dispose()
    $stream.Dispose()
    return ,$bytes
}
function New-TicketBytes {
    $stream = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new($stream)
    Write-HexBytes $writer "00010002"
    Write-Zeros $writer 0x3c
    Write-Zeros $writer 0x40
    Write-Zeros $writer 0x40
    Write-Zeros $writer 0x3c
    Write-Zeros $writer 3
    Write-Zeros $writer 16
    Write-Zeros $writer 1
    Write-U64Be $writer (Convert-HexU64 "0000000000000000")
    Write-U32Be $writer (Convert-HexU32 "00000000")
    Write-U64Be $writer (Convert-HexU64 "000400000ff40ff4")
    Write-Zeros $writer 2
    Write-U16Be $writer 1
    Write-Zeros $writer 8
    Write-Zeros $writer 2
    Write-Zeros $writer 42
    Write-U32Be $writer (Convert-HexU32 "00000000")
    Write-Zeros $writer 1
    Write-Zeros $writer 1
    Write-Zeros $writer 66
    Write-Zeros $writer 64
    Write-U32Be $writer (Convert-HexU32 "00000000")
    Write-U32Be $writer (Convert-HexU32 "00000008")
    $bytes = $stream.ToArray()
    $writer.Dispose()
    $stream.Dispose()
    return ,$bytes
}

$cert = [byte[]] (New-CertificateBytes)
$certChain = New-Object byte[] ($cert.Length * 3)
[Array]::Copy($cert, 0, $certChain, 0, $cert.Length)
[Array]::Copy($cert, 0, $certChain, $cert.Length, $cert.Length)
[Array]::Copy($cert, 0, $certChain, $cert.Length * 2, $cert.Length)
$ticket = [byte[]] (New-TicketBytes)
$tmd = New-Object byte[] 64

$stream = [IO.MemoryStream]::new()
$writer = [IO.BinaryWriter]::new($stream)
Write-U32Le $writer 0x2024
Write-U16Le $writer 0
Write-U16Le $writer 0
Write-U32Le $writer ([UInt32] $certChain.Length)
Write-U32Le $writer ([UInt32] $ticket.Length)
Write-U32Le $writer ([UInt32] $tmd.Length)
Write-U32Le $writer 0
Write-U64Le $writer ([UInt64] $cxi.Length)
Write-Zeros $writer 8192
Pad-ToAlign $writer 64
[void] $writer.Write($certChain)
Pad-ToAlign $writer 64
[void] $writer.Write($ticket)
Pad-ToAlign $writer 64
[void] $writer.Write($tmd)
Pad-ToAlign $writer 64
[void] $writer.Write($cxi)

[IO.File]::WriteAllBytes($outPath, $stream.ToArray())
$writer.Dispose()
$stream.Dispose()
Write-Host "Wrote $outPath"
