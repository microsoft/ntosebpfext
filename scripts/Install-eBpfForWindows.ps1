# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Define one parameter that takes the version of eBPF for Windows to install
param(
    [Parameter(Mandatory = $true)]
    [string]$version,

    [string]$DestinationPath = "$env:TEMP\ebpf-for-windows.$version.msi",

    [string]$ExpectedHash,

    [switch]$DownloadOnly
)

# Define the URL to download the eBPF for Windows installer
$installer_url = "https://github.com/microsoft/ebpf-for-windows/releases/download/v%%VER%%/ebpf-for-windows.x64.%%VER%%.msi"
$installer_url = $installer_url -replace "%%VER%%", $version

$knownInstallerHashes = @{
    "1.4.0" = "22C2989DFDEBF7DBCE22602CA7605C36CB805F86E71146F1D63693AA3184894E"
}
if (-not $ExpectedHash) {
    $ExpectedHash = $knownInstallerHashes[$version]
}
if ($ExpectedHash -notmatch '^[0-9A-Fa-f]{64}$') {
    throw "A valid SHA-256 hash is required for eBPF for Windows version '$version'."
}

$installerUri = [System.Uri]$installer_url
if ($installerUri.Scheme -ne "https" -or
    $installerUri.Host -ne "github.com" -or
    -not $installerUri.AbsolutePath.StartsWith("/microsoft/ebpf-for-windows/releases/download/")) {
    throw "Unexpected eBPF for Windows installer URL: '$installer_url'."
}

# Define the path to download the eBPF for Windows installer
$installer_path = $DestinationPath

# Download the eBPF for Windows installer
Invoke-WebRequest -Uri $installer_url -OutFile $installer_path

if (-not (Test-Path $installer_path -PathType Leaf)) {
    throw "Failed to download the eBPF for Windows installer to '$installer_path'."
}

$downloadedHash = (Get-FileHash -Path $installer_path -Algorithm SHA256).Hash
if ($downloadedHash -ne $ExpectedHash) {
    Remove-Item -Path $installer_path -Force -ErrorAction SilentlyContinue
    throw "Checksum mismatch for ${installer_path}: expected $ExpectedHash, got $downloadedHash."
}

if ($DownloadOnly) {
    return
}

# Install eBPF for Windows
$process = Start-Process -FilePath msiexec -ArgumentList "/i `"$installer_path`" /quiet /norestart" -Wait -PassThru
if ($process.ExitCode -notin @(0, 3010)) {
    throw "eBPF for Windows installation failed with exit code $($process.ExitCode)."
}
