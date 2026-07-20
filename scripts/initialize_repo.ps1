# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Make PowerShell-level errors (e.g., command not found, parse errors) terminating so they
# raise exceptions instead of merely writing to the error stream. Without this, a stale
# $LASTEXITCODE from a previous native command could make a failed step look successful.
$ErrorActionPreference = "Stop"

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..

# Read the eBPF-for-Windows version from ntosebpfext.props (single source of truth).
[xml]$props = Get-Content "ntosebpfext.props"
$ebpfVersion = $props.Project.PropertyGroup.eBPFForWindowsVersion
$exportProgramInfoPath = ".\packages\eBPF-for-Windows.x64.$ebpfVersion\build\native\bin\export_program_info.exe"

# Define the commands to run. String entries are run via Invoke-Expression; script block
# entries are invoked directly so their arguments are not re-parsed by the shell. The cmake
# call must be a script block because the CMake generator expression contains '<' and '>'
# characters that Invoke-Expression would otherwise treat as redirection operators.
$commands = @(
    "git submodule update --init --recursive",
    { & cmake -G "Visual Studio 17 2022" -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<CONFIG:FuzzerDebug>:Debug>' },
    "nuget restore ntosebpfext.sln",
    "dotnet restore ntosebpfext.sln",
    $exportProgramInfoPath
)

# Loop through each command and run them sequentially without opening a new window
foreach ($command in $commands) {
    Write-Host ">> Running command: $command"

    # Reset $LASTEXITCODE so a stale value from a previous native command cannot be
    # mistaken for success if this step fails before setting its own exit code.
    $global:LASTEXITCODE = 0

    try {
        if ($command -is [scriptblock]) {
            & $command
        } else {
            Invoke-Expression -Command $command
        }
    } catch {
        # A PowerShell-level failure (command not found, parse error, etc.) throws here.
        Write-Host "Command failed: $($_.Exception.Message)"
        if ($LASTEXITCODE -ne 0) {
            Exit $LASTEXITCODE
        }
        Exit 1
    }

    # Check the exit code for native command failures that do not throw.
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Command failed. Exit code: $LASTEXITCODE"
        Exit  $LASTEXITCODE
    }
}
Write-Host "All commands succeeded."