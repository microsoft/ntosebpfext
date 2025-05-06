# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

$OneBranchArch = $env:ONEBRANCH_ARCH
$OneBranchConfig = $env:ONEBRANCH_CONFIG
$OutputBinFolder = ".\build\bin\$($OneBranchArch)_$($OneBranchConfig)"

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..\..

try {
    Copy-Item .\scripts\onebranch\nuget.config .\nuget.config
    .\scripts\initialize_repo.ps1

    # Copy any scripts that will be packaged into the output folder
    $OutputScriptsFolder = Join-Path $OutputBinFolder "scripts"
    if (-not (Test-Path -Path $OutputScriptsFolder)) {
        New-Item -ItemType Directory -Path $OutputScriptsFolder -Force
    }
    Copy-Item .\scripts\Install-Extension.ps1 $OutputScriptsFolder
} catch {
    throw "Failed to initialize the repository."
}

Get-ChildItem -Path ./external -Filter *.dll -Recurse | Remove-Item
