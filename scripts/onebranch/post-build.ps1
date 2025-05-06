# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Copy signed files from build\bin\amd64[fre|chk] to the output directory and then rebuild the nupkg and msi

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..\..

$OneBranchArch = $env:ONEBRANCH_ARCH
$OneBranchConfig = $env:ONEBRANCH_CONFIG
# Folder where the build output is located. Note that these may not be signed.
$BuildFolder = ".\$($OneBranchArch)\$($OneBranchConfig)"
# Folder where the signed binaries are located.
$SignedOutputFolder = ".\build\bin\$($OneBranchArch)_$($OneBranchConfig)"

# Produce a zip file of the signed binaries
$OutputZipFile = Join-Path $SignedOutputFolder "Build-$($OneBranchArch)-$($OneBranchConfig).zip"
Compress-Archive -Path $SignedOutputFolder -DestinationPath $OutputZipFile

# Copy signed binaries to the build output directory for usage in the nuget package creation.
xcopy /y $SignedOutputFolder $BuildFolder

# Create the nuget package with the signed binaries.
Import-Module "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"  -DevCmdArguments "-arch=x64 -host_arch=x64"
Set-Location $scriptPath\..\..
$SolutionDir = Get-Location
msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false .\tools\nuget\nuget.proj /t:Restore,Build,Pack

# Copy the nuget package to the output directory.
$DestinationNupkgPath = Join-Path $SignedOutputFolder "packages"
if (-not (Test-Path -Path $DestinationNupkgPath)) {
    New-Item -ItemType Directory -Path $DestinationNupkgPath
}
xcopy /y $BuildFolder\*.nupkg $DestinationNupkgPath
