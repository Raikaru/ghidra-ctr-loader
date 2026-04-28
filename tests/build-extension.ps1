# SPDX-License-Identifier: MIT
#
# Build the CTR loader extension inside the local ghidra-mcp container.
#
# Usage:
#   pwsh tests/build-extension.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string] $Container = "ghidra-mcp",

    [Parameter(Mandatory=$false)]
    [string] $GradlePath = "/opt/gradle-8.5/bin/gradle"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$WorkDir = "/tmp/ghidra-ctr-loader-build"
$RepoName = Split-Path -Leaf $RepoRoot
$StageRoot = Join-Path ([IO.Path]::GetTempPath()) "ghidra-ctr-loader-src-$([Guid]::NewGuid().ToString('N'))"
$StageRepo = Join-Path $StageRoot $RepoName

try {
    New-Item -ItemType Directory -Force -Path $StageRepo | Out-Null
    $sourceFiles = git -C $RepoRoot ls-files --cached --others --exclude-standard
    foreach ($file in $sourceFiles) {
        $source = Join-Path $RepoRoot $file
        $dest = Join-Path $StageRepo $file
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
        Copy-Item -LiteralPath $source -Destination $dest
    }

    docker exec $Container bash -lc "rm -rf $WorkDir && mkdir -p $WorkDir" | Out-Null
    docker cp $StageRepo "${Container}:$WorkDir" | Out-Null
    docker exec $Container bash -lc "cd $WorkDir/$RepoName && GHIDRA_INSTALL_DIR=/opt/ghidra JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 '$GradlePath' --no-daemon buildExtension"
    if ($LASTEXITCODE -ne 0) {
        throw "Gradle buildExtension failed"
    }
}
finally {
    if (Test-Path $StageRoot) {
        Remove-Item -Recurse -Force $StageRoot
    }
}

Write-Host "CTR loader build passed in container $Container"
