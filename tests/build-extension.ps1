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

docker exec $Container bash -lc "rm -rf $WorkDir && mkdir -p $WorkDir" | Out-Null
docker cp $RepoRoot "${Container}:$WorkDir" | Out-Null
docker exec $Container bash -lc "cd $WorkDir/$(Split-Path -Leaf $RepoRoot) && GHIDRA_INSTALL_DIR=/opt/ghidra JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 '$GradlePath' --no-daemon buildExtension"

Write-Host "CTR loader build passed in container $Container"
