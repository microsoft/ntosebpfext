# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Define one parameter that takes the version of eBPF for Windows to install
param(
    [string]$version
)

# Define the URL to download the eBPF for Windows installer
$installer_url = "https://github.com/microsoft/ebpf-for-windows/releases/download/Release-v%%VER%%/ebpf-for-windows.%%VER%%.msi"
$installer_url = $installer_url -replace "%%VER%%", $version

# Define the path to download the eBPF for Windows installer
$installer_path = "$env:TEMP\ebpf-for-windows.$version.msi"

# Download the eBPF for Windows installer
Invoke-WebRequest -Uri $installer_url -OutFile $installer_path

# Install eBPF for Windows
Start-Process -FilePath msiexec -ArgumentList "/i $installer_path /quiet" -Wait
