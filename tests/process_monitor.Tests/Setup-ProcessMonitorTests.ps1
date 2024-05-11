# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# .SYNOPSIS
# Set up the environment for testing the Process Monitor tool functionality.

param(
    [string]$ArtifactsRoot
)

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
    $ArtifactsRootFullPath = (Get-Item -Path $ArtifactsRoot).FullName

    Write-Output "Creating and starting the ntosebpfext service from $ArtifactsRootFullPath\ntosebpfext.sys."
    Start-Process -FilePath "sc" -ArgumentList "create ntosebpfext type= kernel binPath= $ArtifactsRootFullPath\ntosebpfext.sys start= auto " -Wait
    Start-Service -Name "ntosebpfext"
}

# Check if the ntosebpfext service is running.
$service_status = Get-Service -Name "ntosebpfext" -ErrorAction SilentlyContinue

if ($service_status.Status -ne "Running") {
    Write-Output "The ntosebpfext service is not running."
    Write-Output "Please start the ntosebpfext service before running this script."
    exit 1
}

exit 0