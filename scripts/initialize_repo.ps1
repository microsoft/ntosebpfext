# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..

# Read the eBPF-for-Windows version from ntosebpfext.props (single source of truth).
[xml]$props = Get-Content "ntosebpfext.props"
$ebpfVersion = $props.Project.PropertyGroup.eBPFForWindowsVersion
$exportProgramInfoPath = ".\packages\eBPF-for-Windows.x64.$ebpfVersion\build\native\bin\export_program_info.exe"

# Auto-detect the installed Visual Studio version to pick the matching CMake generator, so this works
# on machines/runners with Visual Studio 2022 (v17) or Visual Studio 2026 (v18) installed.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$cmakeGenerator = "Visual Studio 17 2022"
if (Test-Path $vswhere) {
    $vsMajor = ((& $vswhere -latest -property installationVersion | Select-Object -First 1) -split '\.' | Select-Object -First 1)
    switch ($vsMajor) {
        "18" { $cmakeGenerator = "Visual Studio 18 2026" }
        "17" { $cmakeGenerator = "Visual Studio 17 2022" }
        default {
            if ($vsMajor) {
                Write-Warning "Unrecognized Visual Studio major version '$vsMajor'; defaulting to the Visual Studio 2022 generator."
            }
        }
    }
} else {
    Write-Warning "vswhere.exe not found at '$vswhere'; defaulting to the Visual Studio 2022 generator."
}
Write-Host "Using CMake generator: $cmakeGenerator"

# Define the commands to run
$commands = @(
    "git submodule update --init --recursive",
    "cmake -G `"$cmakeGenerator`" -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF",
    "nuget restore ntosebpfext.sln",
    "dotnet restore ntosebpfext.sln",
    $exportProgramInfoPath
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