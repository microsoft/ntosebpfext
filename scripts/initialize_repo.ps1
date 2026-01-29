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
$commands = @(
    "git submodule update --init --recursive",
    "cmake -G 'Visual Studio 17 2022' -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF",
    "dotnet restore ntosebpfext.sln",
    "`"$ebpfToolPath`""
)

# Loop through each command and run them sequentially without opening a new window
foreach ($command in $commands) {
    Write-Host ">> Running command: $command"
    Invoke-Expression -Command $command

    # Check the exit code
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Command failed. Exit code: $LASTEXITCODE"
        Exit  $LASTEXITCODE
    }
}
Write-Host "All commands succeeded."