# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Define one parameter that takes the version of eBPF for Windows to install
param(
    [Parameter(Mandatory = $true)]
    [string]$version,

    [string]$DestinationPath = "$env:TEMP\ebpf-for-windows.$version.msi",

    [switch]$DownloadOnly
)

# Define the URL to download the eBPF for Windows installer
$installer_url = "https://github.com/microsoft/ebpf-for-windows/releases/download/v%%VER%%/ebpf-for-windows.x64.%%VER%%.msi"
$installer_url = $installer_url -replace "%%VER%%", $version

# Define the path to download the eBPF for Windows installer
$installer_path = $DestinationPath

# Download the eBPF for Windows installer
Invoke-WebRequest -Uri $installer_url -OutFile $installer_path

if (-not (Test-Path $installer_path -PathType Leaf)) {
    throw "Failed to download the eBPF for Windows installer to '$installer_path'."
}

if ($DownloadOnly) {
    return
}

# Install eBPF for Windows
$process = Start-Process -FilePath msiexec -ArgumentList "/i `"$installer_path`" /quiet /norestart" -Wait -PassThru
if ($process.ExitCode -notin @(0, 3010)) {
    throw "eBPF for Windows installation failed with exit code $($process.ExitCode)."
}
