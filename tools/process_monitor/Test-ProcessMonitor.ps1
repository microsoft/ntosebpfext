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

# Start Process_Montior.exe, redirect the output to a file.
Start-Process -FilePath ".\Process_Monitor.exe" -RedirectStandardOutput ".\process_monitor_output.txt"  -PassThru -RedirectStandardError ".\process_monitor_error.txt"0.15.0

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

# Wait for the Process Monitor to capture the process.
Start-Sleep -Seconds 5

# Stop Process_Monitor.exe
Get-Process -name Process_Monitor | stop-process

# Print the output file content for debugging.
Write-Output "Process Monitor output file content:"
Get-Content -Path "process_monitor_output.txt"

# Check if the output file is created.
if (Test-Path -Path "process_monitor_output.txt") {
    Write-Output "Process Monitor output file is created."
} else {
    Write-Output "Process Monitor output file is not created."
    exit 1
}

# Check if the output file is not empty.
if ((Get-Content -Path "process_monitor_output.txt") -eq "") {
    Write-Output "Process Monitor output file is empty."
    exit 1
}

# Check for the process name in the output file.
if ((Get-Content -Path "process_monitor_output.txt") -match "cmd.exe") {
    Write-Output "Process Monitor output file contains the expected string."
} else {
    Write-Output "Process Monitor output file does not contain the expected string."
    exit 1
}

# Check for the process command in the output file.
if ((Get-Content -Path "process_monitor_output.txt") -match "/c echo Hello World ") {
    Write-Output "Process Monitor output file contains the expected string."
} else {
    Write-Output "Process Monitor output file does not contain the expected string."
    exit 1
}

exit 0