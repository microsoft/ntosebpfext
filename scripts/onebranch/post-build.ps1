# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Copy signed files from build\bin\amd64[fre|chk] to the output directory and then rebuild the nupkg and msi

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..\..

$OneBranchArch = $env:ONEBRANCH_ARCH
$OneBranchConfig = $env:ONEBRANCH_CONFIG

function Copy-BuildFolder {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Release", "Debug")]
        [string]$Configuration, 
        [Parameter(Mandatory=$true)]
        [string]$Arch
    )

    # Define the source folder and zip file path based on the configuration
    $SourceFolder = ".\$Arch\$Configuration"
    $ZipFile = ".\build\bin\$($Arch)_$($Configuration)\Build-$($Arch)-$($Configuration).zip"

    # Remove any existing zip file to avoid conflicts
    if (Test-Path $ZipFile) {
        Remove-Item $ZipFile
    }

    # Compress the folder into a zip file
    Compress-Archive -Path $SourceFolder -DestinationPath $ZipFile

    Write-Host "$SourceFolder folder has been zipped into $ZipFile"
}

# Copy the signed binaries to the output directory
if ($OneBranchConfig -eq "Debug" -and $OneBranchArch -eq "x64") {
    xcopy /y build\bin\x64_Debug .\x64\Debug
    xcopy /y build\bin\x64_Debug\Install-Extension.ps1 .\scripts\
    Get-ChildItem -Path .\build\bin\x64_Debug -Recurse | Remove-Item -Force -Recurse
}
elseif ($OneBranchConfig -eq "Release" -and $OneBranchArch -eq "x64") {
    xcopy /y build\bin\x64_Release .\x64\Release
    xcopy /y build\bin\x64_Release\Install-Extension.ps1 .\scripts\
    Get-ChildItem -Path .\build\bin\x64_Release -Recurse | Remove-Item -Force -Recurse
}
else {
    throw ("Configuration $OneBranchConfig|$OneBranchArch is not supported.")
}

Import-Module "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"  -DevCmdArguments "-arch=x64 -host_arch=x64"
Set-Location $scriptPath\..\..
$SolutionDir = Get-Location
msbuild /p:SolutionDir=$SolutionDir\ /p:Configuration=$OneBranchConfig /p:Platform=$OneBranchArch /p:BuildProjectReferences=false .\tools\nuget\nuget.proj /t:Restore,Build,Pack

$SourceNupkgPath = ".\$OneBranchArch\$OneBranchConfig\*.nupkg"
# Copy the nupkg to the 'packages' subdirectory in the output directory (default used by onebranch pipelines to publish nupkgs)
$DestinationNupkgPath = ".\build\bin\$OneBranchArch`_$OneBranchConfig\packages"

if (-not (Test-Path -Path $DestinationNupkgPath)) {
    New-Item -ItemType Directory -Path $DestinationNupkgPath
}

xcopy /y $SourceNupkgPath $DestinationNupkgPath
Copy-BuildFolder -Configuration $OneBranchConfig -Arch $OneBranchArch