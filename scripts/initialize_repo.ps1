# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..

# Define the commands to run
# Resolve NuGet global packages location dynamically
$nugetPackagesPath = if ($env:NUGET_PACKAGES) { 
    $env:NUGET_PACKAGES 
} else { 
    & dotnet nuget locals global-packages --list | ForEach-Object { 
        if ($_ -match 'global-packages: (.+)') { $matches[1] } 
    }
}

# Derive the eBPF-for-Windows package version from Directory.Packages.props
$packagesPropsPath = Join-Path (Get-Location) "Directory.Packages.props"
[xml]$packagesPropsXml = Get-Content $packagesPropsPath
$ebpfPackageNode = $packagesPropsXml.Project.ItemGroup.PackageVersion | Where-Object { $_.Include -eq 'eBPF-for-Windows.x64' }
$ebpfVersion = $ebpfPackageNode.Version

$ebpfToolPath = Join-Path $nugetPackagesPath "ebpf-for-windows.x64\$ebpfVersion\build\native\bin\export_program_info.exe"

# Execute commands sequentially
Write-Host ">> Running command: git submodule update --init --recursive"
git submodule update --init --recursive
if ($LASTEXITCODE -ne 0) {
    Write-Host "Command failed. Exit code: $LASTEXITCODE"
    Exit $LASTEXITCODE
}

Write-Host ">> Running command: cmake -G 'Visual Studio 17 2022' -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF"
cmake -G 'Visual Studio 17 2022' -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF
if ($LASTEXITCODE -ne 0) {
    Write-Host "Command failed. Exit code: $LASTEXITCODE"
    Exit $LASTEXITCODE
}

Write-Host ">> Running command: dotnet restore ntosebpfext.sln"
dotnet restore ntosebpfext.sln
if ($LASTEXITCODE -ne 0) {
    Write-Host "Command failed. Exit code: $LASTEXITCODE"
    Exit $LASTEXITCODE
}

Write-Host ">> Running command: $ebpfToolPath"
& $ebpfToolPath
if ($LASTEXITCODE -ne 0) {
    Write-Host "Command failed. Exit code: $LASTEXITCODE"
    Exit $LASTEXITCODE
}

Write-Host "All commands succeeded."