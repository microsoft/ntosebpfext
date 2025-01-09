# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..\..

try {
    Copy-Item .\scripts\onebranch\nuget.config .\nuget.config
    .\scripts\initialize_repo.ps1
}
catch {
    throw "Failed to initialize the repository."
}

Get-ChildItem -Path ./external -Filter *.dll -Recurse | Remove-Item
