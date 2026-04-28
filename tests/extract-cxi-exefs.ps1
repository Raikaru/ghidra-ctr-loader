# SPDX-License-Identifier: MIT
#
# Extract ExeFS members from a private decrypted NCCH/CXI image into ignored
# local test space. Do not commit the output.
#
# Usage:
#   pwsh tests/extract-cxi-exefs.ps1 -InputPath "C:\path\to\decrypted.cxi"

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
    $OutDir = Join-Path $RepoRoot ".local-test\exefs\$stem"
} elseif (-not [IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path $RepoRoot $OutDir
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Read-Int32LeFromBytes([byte[]] $Data, [int] $Offset) {
    return [BitConverter]::ToInt32($Data, $Offset)
}

function Expand-CodeLzss([byte[]] $Code) {
    $offSizeComp = Read-Int32LeFromBytes $Code ($Code.Length - 8)
    $addSize = Read-Int32LeFromBytes $Code ($Code.Length - 4)
    $compStart = 0
    $codeLen = $Code.Length
    $codeCompSize = $offSizeComp -band 0xffffff
    $codeCompEnd = $codeCompSize - (($offSizeComp -shr 24) -band 0xff)
    $codeDecSize = $codeLen + $addSize

    if ($codeCompSize -le $codeLen) {
        $compStart = $codeLen - $codeCompSize
    }

    $dec = New-Object byte[] $codeDecSize
    [Array]::Copy($Code, 0, $dec, 0, $Code.Length)

    $dataEnd = $compStart + $codeDecSize
    $ptrIn = $compStart + $codeCompEnd
    $ptrOut = $codeDecSize

    while ($ptrIn -gt $compStart -and $ptrOut -gt $compStart) {
        if ($ptrOut -lt $ptrIn) {
            throw "LZSS decode failed: ptrOut < ptrIn"
        }

        $ptrIn--
        $ctrlByte = [int] $dec[$ptrIn]
        for ($i = 7; $i -ge 0; $i--) {
            if ($ptrIn -le $compStart -or $ptrOut -le $compStart) {
                break
            }

            if ((($ctrlByte -shr $i) -band 1) -ne 0) {
                $ptrIn -= 2
                if ($ptrIn -lt $compStart) {
                    throw "LZSS decode failed: ptrIn < compStart"
                }

                $segCode = [BitConverter]::ToUInt16($dec, $ptrIn)
                $segOff = ($segCode -band 0xfff) + 2
                $segLen = (($segCode -shr 12) -band 0xf) + 3

                if ($ptrOut - $segLen -lt $compStart) {
                    throw "LZSS decode failed: ptrOut - segLen < compStart"
                }
                if ($ptrOut + $segOff -ge $dataEnd) {
                    throw "LZSS decode failed: ptrOut + segOff >= dataEnd"
                }

                for ($c = 0; $c -lt $segLen; $c++) {
                    $data = $dec[$ptrOut + $segOff]
                    $ptrOut--
                    $dec[$ptrOut] = $data
                }
            } else {
                $ptrOut--
                $ptrIn--
                $dec[$ptrOut] = $dec[$ptrIn]
            }
        }
    }

    if ($ptrIn -ne $compStart) {
        throw "LZSS decode failed: ptrIn != compStart"
    }
    if ($ptrOut -ne $compStart) {
        throw "LZSS decode failed: ptrOut != compStart"
    }

    return $dec
}

function Read-CodeSetInfo([IO.BinaryReader] $Reader, [int64] $Offset) {
    $Reader.BaseStream.Position = $Offset
    $address = $Reader.ReadUInt32()
    $physicalPages = $Reader.ReadUInt32()
    $size = $Reader.ReadUInt32()
    return [pscustomobject]@{
        address = ("0x{0:x8}" -f $address)
        address_value = $address
        physical_pages = $physicalPages
        physical_size = $physicalPages * 0x1000L
        size = $size
    }
}

$fs = [IO.File]::OpenRead($InputPath)
$br = [IO.BinaryReader]::new($fs)
try {
    $fs.Position = 0x100
    $magic = [Text.Encoding]::ASCII.GetString($br.ReadBytes(4))
    if ($magic -ne "NCCH") {
        throw "Expected NCCH magic at 0x100, got '$magic'"
    }

    $fs.Position = 0x20d
    $exheaderFlags = $br.ReadByte()
    $codeCompressed = (($exheaderFlags -band 0x1) -ne 0)

    $textCodeSet = Read-CodeSetInfo $br 0x210
    $rodataCodeSet = Read-CodeSetInfo $br 0x220
    $dataCodeSet = Read-CodeSetInfo $br 0x230
    $fs.Position = 0x23c
    $bssSize = $br.ReadUInt32()

    $fs.Position = 0x1a0
    $exefsOffsetMedia = $br.ReadUInt32()
    $exefsSizeMedia = $br.ReadUInt32()
    $null = $br.ReadUInt32()
    $null = $br.ReadUInt32()
    $exefsOffset = [int64] $exefsOffsetMedia * 0x200L
    $exefsSize = [int64] $exefsSizeMedia * 0x200L
    if ($exefsOffset -le 0 -or $exefsSize -le 0) {
        throw "No ExeFS region found"
    }

    $entries = @()
    $fs.Position = $exefsOffset
    for ($i = 0; $i -lt 10; $i++) {
        $name = [Text.Encoding]::ASCII.GetString($br.ReadBytes(8)).Trim([char] 0)
        $offset = $br.ReadUInt32()
        $size = $br.ReadUInt32()
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $entries += [pscustomobject]@{
                Name = $name
                Offset = $offset
                Size = $size
            }
        }
    }

    $dataStart = $exefsOffset + 0x200L
    foreach ($entry in $entries) {
        $safeName = $entry.Name -replace '[^A-Za-z0-9_.-]', '_'
        $outPath = Join-Path $OutDir $safeName
        $fs.Position = $dataStart + [int64] $entry.Offset
        $entryBytes = $br.ReadBytes([int] $entry.Size)
        if ($entry.Name -eq ".code" -and $codeCompressed) {
            $entryBytes = Expand-CodeLzss $entryBytes
        }
        [IO.File]::WriteAllBytes($outPath, $entryBytes)
    }

    $manifest = [pscustomobject]@{
        source_name = [IO.Path]::GetFileName($InputPath)
        exefs_offset = ("0x{0:x}" -f $exefsOffset)
        exefs_size = ("0x{0:x}" -f $exefsSize)
        code_compressed = $codeCompressed
        code_set = [pscustomobject]@{
            text = $textCodeSet
            rodata = $rodataCodeSet
            data = $dataCodeSet
            bss = [pscustomobject]@{
                address = ("0x{0:x8}" -f ($dataCodeSet.address_value + $dataCodeSet.size))
                address_value = $dataCodeSet.address_value + $dataCodeSet.size
                size = $bssSize
            }
        }
        files = @($entries | ForEach-Object {
            $safeName = $_.Name -replace '[^A-Za-z0-9_.-]', '_'
            $outPath = Join-Path $OutDir $safeName
            [pscustomobject]@{
                name = $_.Name
                stored_size = $_.Size
                extracted_size = (Get-Item -LiteralPath $outPath).Length
            }
        })
    }
    $manifestPath = Join-Path $OutDir "manifest.structure.json"
    $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestPath -Encoding utf8
    Write-Host "Wrote ExeFS files to $OutDir"
    Write-Host "Wrote $manifestPath"
} finally {
    $br.Dispose()
    $fs.Dispose()
}
