# SPDX-License-Identifier: MIT
#
# Emit a payload-safe RomFS file listing for a private decrypted NCCH/CXI image.
# The output records paths and sizes only, never file data.
#
# Usage:
#   pwsh tests/list-cxi-romfs.ps1 -InputPath "C:\path\to\decrypted.cxi"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $InputPath,

    [Parameter(Mandatory=$false)]
    [string] $OutPath = "",

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
    $OutDir = Join-Path $RepoRoot ".local-test\romfs-list"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if ([string]::IsNullOrWhiteSpace($OutPath)) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($InputPath) -replace '[^A-Za-z0-9_.-]', '_'
    $OutPath = Join-Path $OutDir "$stem.romfs.structure.json"
}

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
    $level3Length = $br.ReadInt32()
    $dirHashOffset = $br.ReadInt32()
    $dirHashSize = $br.ReadInt32()
    $dirMetaOffset = $br.ReadInt32()
    $dirMetaSize = $br.ReadInt32()
    $fileHashOffset = $br.ReadInt32()
    $fileHashSize = $br.ReadInt32()
    $fileMetaOffset = $br.ReadInt32()
    $fileMetaSize = $br.ReadInt32()
    $fileDataOffset = $br.ReadInt32()

    $dirMetaBase = $level3Start + $dirMetaOffset
    $fileMetaBase = $level3Start + $fileMetaOffset
    $files = New-Object System.Collections.Generic.List[object]
    $directories = New-Object System.Collections.Generic.List[string]

    function Walk-Directory([int] $Offset, [string] $ParentPath) {
        $dir = Read-Directory $br $dirMetaBase $Offset
        $dirPath = if ([string]::IsNullOrWhiteSpace($dir.name)) { $ParentPath } else { "$ParentPath/$($dir.name)" }
        if ([string]::IsNullOrWhiteSpace($dirPath)) {
            $dirPath = "/"
        }
        $directories.Add($dirPath) | Out-Null

        $childDirOffset = $dir.child_dir
        while ($childDirOffset -ne -1) {
            Walk-Directory $childDirOffset $dirPath
            $child = Read-Directory $br $dirMetaBase $childDirOffset
            $childDirOffset = $child.sibling
        }

        $childFileOffset = $dir.child_file
        while ($childFileOffset -ne -1) {
            $file = Read-FileEntry $br $fileMetaBase $childFileOffset
            $filePath = if ($dirPath -eq "/") { "/$($file.name)" } else { "$dirPath/$($file.name)" }
            $files.Add([pscustomobject]@{
                path = $filePath
                size = $file.size
            }) | Out-Null
            $childFileOffset = $file.sibling
        }
    }

    Walk-Directory 0 ""

    $extensions = @($files | ForEach-Object {
        $ext = [IO.Path]::GetExtension($_.path)
        if ([string]::IsNullOrWhiteSpace($ext)) { "<none>" } else { $ext.ToLowerInvariant() }
    } | Group-Object | Sort-Object Count -Descending | ForEach-Object {
        [pscustomobject]@{
            extension = $_.Name
            count = $_.Count
        }
    })

    $summary = [pscustomobject]@{
        source_name = [IO.Path]::GetFileName($InputPath)
        romfs_offset = ("0x{0:x}" -f $romfsOffset)
        romfs_size = ("0x{0:x}" -f $romfsSize)
        level3_length = $level3Length
        directory_count = $directories.Count
        file_count = $files.Count
        total_file_bytes = @($files | Measure-Object -Property size -Sum)[0].Sum
        extensions = $extensions
        directories = @($directories | Sort-Object)
        files = @($files | Sort-Object path)
    }

    $summary | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutPath -Encoding utf8
    Write-Host "Wrote $OutPath"
} finally {
    $br.Dispose()
    $fs.Dispose()
}
