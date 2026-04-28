# SPDX-License-Identifier: MIT
#
# Extract one RomFS member from a private decrypted NCCH/CXI image into ignored
# local test space. Do not commit the output.
#
# Usage:
#   pwsh tests/extract-cxi-romfs-file.ps1 `
#     -InputPath "C:\path\to\decrypted.cxi" `
#     -RomFsPath "/module/game.cro"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $InputPath,

    [Parameter(Mandatory=$true)]
    [string] $RomFsPath,

    [Parameter(Mandatory=$false)]
    [string] $OutDir = "",

    [Parameter(Mandatory=$false)]
    [string] $OutPath = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $InputPath)) {
    throw "Input path not found: $InputPath"
}
if (-not $RomFsPath.StartsWith("/")) {
    throw "RomFS path must start with '/': $RomFsPath"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($InputPath) -replace '[^A-Za-z0-9_.-]', '_'
    $OutDir = Join-Path $RepoRoot ".local-test\romfs-extract\$stem"
} elseif (-not [IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path $RepoRoot $OutDir
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Read-Utf16Name([IO.BinaryReader] $Reader, [int] $ByteLength) {
    if ($ByteLength -le 0) {
        return ""
    }
    return [Text.Encoding]::Unicode.GetString($Reader.ReadBytes($ByteLength))
}

function Align-Stream([IO.Stream] $Stream, [int] $Align) {
    $padding = ($Align - ($Stream.Position % $Align)) % $Align
    if ($padding -gt 0) {
        $Stream.Position += $padding
    }
}

function Read-Directory([IO.BinaryReader] $Reader, [int64] $Base, [int64] $Offset) {
    $Reader.BaseStream.Position = $Base + $Offset
    $parent = $Reader.ReadInt32()
    $sibling = $Reader.ReadInt32()
    $childDir = $Reader.ReadInt32()
    $childFile = $Reader.ReadInt32()
    $bucketNext = $Reader.ReadInt32()
    $nameSize = $Reader.ReadInt32()
    $name = Read-Utf16Name $Reader $nameSize
    Align-Stream $Reader.BaseStream 4
    return [pscustomobject]@{
        parent = $parent
        sibling = $sibling
        child_dir = $childDir
        child_file = $childFile
        bucket_next = $bucketNext
        name = $name
    }
}

function Read-FileEntry([IO.BinaryReader] $Reader, [int64] $Base, [int64] $Offset) {
    $Reader.BaseStream.Position = $Base + $Offset
    $directory = $Reader.ReadInt32()
    $sibling = $Reader.ReadInt32()
    $dataOffset = $Reader.ReadUInt64()
    $dataSize = $Reader.ReadUInt64()
    $bucketNext = $Reader.ReadInt32()
    $nameSize = $Reader.ReadInt32()
    $name = Read-Utf16Name $Reader $nameSize
    Align-Stream $Reader.BaseStream 4
    return [pscustomobject]@{
        directory = $directory
        sibling = $sibling
        data_offset = $dataOffset
        size = $dataSize
        bucket_next = $bucketNext
        name = $name
    }
}

function Join-RomFsPath([string] $ParentPath, [string] $Name) {
    if ([string]::IsNullOrWhiteSpace($Name)) {
        if ([string]::IsNullOrWhiteSpace($ParentPath)) { return "/" }
        return $ParentPath
    }
    if ([string]::IsNullOrWhiteSpace($ParentPath) -or $ParentPath -eq "/") {
        return "/$Name"
    }
    return "$ParentPath/$Name"
}

$targetParts = ($RomFsPath -replace '\\', '/') -split '/' | Where-Object { $_ -ne "" }
$normalizedTarget = "/" + ($targetParts -join "/")
$safeName = ($normalizedTarget.TrimStart("/") -replace '[\\/]+', "__") -replace '[^A-Za-z0-9_.-]', '_'
if ([string]::IsNullOrWhiteSpace($OutPath)) {
    $OutPath = Join-Path $OutDir $safeName
} elseif (-not [IO.Path]::IsPathRooted($OutPath)) {
    $OutPath = Join-Path $RepoRoot $OutPath
}

$fs = [IO.File]::OpenRead($InputPath)
$br = [IO.BinaryReader]::new($fs)
try {
    $fs.Position = 0x100
    $magic = [Text.Encoding]::ASCII.GetString($br.ReadBytes(4))
    if ($magic -ne "NCCH") {
        throw "Expected NCCH magic at 0x100, got '$magic'"
    }

    $fs.Position = 0x1b0
    $romfsOffsetMedia = $br.ReadUInt32()
    $romfsSizeMedia = $br.ReadUInt32()
    $romfsOffset = [int64] $romfsOffsetMedia * 0x200L
    $romfsSize = [int64] $romfsSizeMedia * 0x200L
    if ($romfsOffset -le 0 -or $romfsSize -le 0) {
        throw "No RomFS region found"
    }

    $level3Start = $romfsOffset + 0x1000L
    $fs.Position = $level3Start
    $null = $br.ReadInt32()
    $null = $br.ReadInt32()
    $null = $br.ReadInt32()
    $dirMetaOffset = $br.ReadInt32()
    $null = $br.ReadInt32()
    $null = $br.ReadInt32()
    $null = $br.ReadInt32()
    $fileMetaOffset = $br.ReadInt32()
    $null = $br.ReadInt32()
    $fileDataOffset = $br.ReadInt32()

    $dirMetaBase = $level3Start + $dirMetaOffset
    $fileMetaBase = $level3Start + $fileMetaOffset
    $script:found = $null

    function Walk-Directory([int] $Offset, [string] $ParentPath) {
        $dir = Read-Directory $br $dirMetaBase $Offset
        $dirPath = Join-RomFsPath $ParentPath $dir.name
        if ([string]::IsNullOrWhiteSpace($dirPath)) {
            $dirPath = "/"
        }

        $childFileOffset = $dir.child_file
        while ($childFileOffset -ne -1) {
            $file = Read-FileEntry $br $fileMetaBase $childFileOffset
            $filePath = Join-RomFsPath $dirPath $file.name
            if ($filePath -eq $normalizedTarget) {
                $script:found = [pscustomobject]@{
                    path = $filePath
                    data_offset = $file.data_offset
                    size = $file.size
                }
                return
            }
            $childFileOffset = $file.sibling
        }

        $childDirOffset = $dir.child_dir
        while ($childDirOffset -ne -1 -and $null -eq $script:found) {
            Walk-Directory $childDirOffset $dirPath
            $child = Read-Directory $br $dirMetaBase $childDirOffset
            $childDirOffset = $child.sibling
        }
    }

    Walk-Directory 0 ""
    if ($null -eq $script:found) {
        throw "RomFS file not found: $normalizedTarget"
    }

    $parent = Split-Path -Parent $OutPath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    $sourceOffset = $level3Start + $fileDataOffset + [int64] $script:found.data_offset
    $fs.Position = $sourceOffset
    $out = [IO.File]::Create($OutPath)
    try {
        $remaining = [int64] $script:found.size
        $buffer = New-Object byte[] 1048576
        while ($remaining -gt 0) {
            $wanted = [int] [Math]::Min($buffer.Length, $remaining)
            $read = $fs.Read($buffer, 0, $wanted)
            if ($read -le 0) {
                throw "Unexpected EOF while extracting $normalizedTarget"
            }
            $out.Write($buffer, 0, $read)
            $remaining -= $read
        }
    } finally {
        $out.Dispose()
    }

    Write-Host "Wrote $OutPath"
} finally {
    $br.Dispose()
    $fs.Dispose()
}
