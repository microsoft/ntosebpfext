# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Define the commands to run
$commands = @(
    "git submodule update --init --recursive",
    "cmake -G 'Visual Studio 17 2022' -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF",
    "nuget restore ntosebpfext.sln",
    "packages\eBPF-for-Windows.0.16.0\build\native\bin\export_program_info.exe"
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