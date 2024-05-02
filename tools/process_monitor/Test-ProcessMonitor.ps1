# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# .SYNOPSIS
# Test the Process Monitor tool functionality.

# Check if eBPF for Windows is installed.
$service_status = Get-Service -Name "ebpfcore" -ErrorAction SilentlyContinue

if ($service_status -eq $null) {
    Write-Output "eBPF for Windows is not installed."
    Write-Output "Please install eBPF for Windows before running this script."
    exit 1
}

# Check if the ntosebpfext service is running.
$service_status = Get-Service -Name "ntosebpfext" -ErrorAction SilentlyContinue

# If the service is not present create and start the service.
if ($service_status -eq $null) {
    Write-Output "Creating and starting the ntosebpfext service."
    Start-Process -FilePath "sc" -ArgumentList "create ntosebpfext type= kernel binPath= $PSScriptRoot\ntosebpfext.sys start= auto " -Wait
    Start-Service -Name "ntosebpfext"
}

# Check if the ntosebpfext service is running.
$service_status = Get-Service -Name "ntosebpfext" -ErrorAction SilentlyContinue

if ($service_status.Status -ne "Running") {
    Write-Output "The ntosebpfext service is not running."
    Write-Output "Please start the ntosebpfext service before running this script."
    exit 1
}

# Ensure the output txt file is deleted before we run, in case this test suite is being run locally for development/debugging
$outputFilePath = ".\process_monitor_output.txt";
if (Test-Path $outputFilePath)
{
    Remove-Item $outputFilePath
}

# Start Process_Montior.exe, redirect the output to a file.
Start-Process -FilePath ".\Process_Monitor.exe" -RedirectStandardOutput $outputFilePath  -PassThru #-RedirectStandardError $outputFilePath+".err"

# Wait for the Process Monitor to start.
Start-Sleep -Seconds 5

# Check if the Process Monitor is running.
if (Get-Process -name Process_Monitor) {
    Write-Output "Process Monitor is running."
} else {
    Write-Output "Process Monitor is not running."
    exit 1
}

# Start a test process.
Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo Hello World" -Wait
Start-Process -FilePath "cmd.exe" -ArgumentList "/c exit 1" -Wait
Start-Process -FilePath "cmd.exe" -ArgumentList "/c exit 235" -Wait

# Wait for the Process Monitor to capture the processes.
Start-Sleep -Seconds 5

# Stop Process_Monitor.exe
Get-Process -name Process_Monitor | stop-process

# Print the output file content for debugging.
Write-Output "Process Monitor output file content:"
Get-Content -Path $outputFilePath

# Check if the output file is created.
if (Test-Path -Path $outputFilePath) {
    Write-Output "Process Monitor output file is created."
} else {
    Write-Output "Process Monitor output file is not created."
    exit 1
}

# Check for the process name in the output file.
if ((Get-Content -Path $outputFilePath) -match "cmd.exe") {
    Write-Output "Process Monitor output file contains the expected string (cmd.exe)."
} else {
    Write-Output "Process Monitor output file does not contain the expected string (cmd.exe)."
    exit 1
}

# Check for the process command in the output file.
if ((Get-Content -Path $outputFilePath) -match "/c echo Hello World ") {
    Write-Output "Process Monitor output file contains the expected string (/c echo Hello World )."
} else {
    Write-Output "Process Monitor output file does not contain the expected string (/c echo Hello World )."
    exit 1
}

# Check that we saw the error codes correctly flowing through
if ((Get-Content -Path $outputFilePath) -match ", exit code: 1 ") {
    Write-Output "Process Monitor output file contains the expected string (, exit code: 1 )."
} else {
    Write-Output "Process Monitor output file does not contain the expected string (, exit code: 1 )."
    exit 1
}

if ((Get-Content -Path $outputFilePath) -match ", exit code: 235 ") {
    Write-Output "Process Monitor output file contains the expected string (, exit code: 235 )."
} else {
    Write-Output "Process Monitor output file does not contain the expected string (, exit code: 235 )."
    exit 1
}

exit 0