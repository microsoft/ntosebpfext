# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ($majorVersion, $minorVersion, $revisionNumber)

# Check if the version number is in the format X.Y.Z
if ("$majorVersion.$minorVersion.$revisionNumber" -match '^\d+\.\d+\.\d+$') {

    if (Test-Path -Path ".\ntosebpfext.sln") {
        # Set the new version number in the ebpf_version.h file.
        $ntosebpfext_version_file = "$PSScriptRoot\..\Directory.Build.props"
        Write-Host -ForegroundColor DarkGreen "Updating the version number in the '$ntosebpfext_version_file' file..."
        # Replace <eBPFExtensionsVersionMajor>0</eBPFExtensionsVersionMajor> with <eBPFExtensionsVersionMajor>$majorVersion</eBPFExtensionsVersionMajor>
        $newcontent = (Get-Content $ntosebpfext_version_file -Raw -Encoding UTF8) `
                        -replace '(?<=<eBPFExtensionsVersionMajor>)\d+', $majorVersion `
                        -replace '(?<=<eBPFExtensionsVersionMinor>)\d+', $minorVersion `
                        -replace '(?<=<eBPFExtensionsVersionRevision>)\d+', $revisionNumber

        $newcontent | Set-Content $ntosebpfext_version_file -NoNewline
        Write-Host -ForegroundColor DarkGreen "Version number updated to '$majorVersion.$minorVersion.$revisionNumber' in $ntosebpfext_version_file"

    } else {
        Write-Host -ForegroundColor Red "'ntosebpfext.sln' not found in the current path."
        Write-Host -ForegroundColor DarkYellow "Please run this script from the root directory of the repository, within a Developer Poweshell for VS 2022."
    }
} else {
    Write-Host -ForegroundColor Red "Invalid version number format. Please enter the version number in the format 'X Y Z', e.g.:"
    Write-Host
    Write-Host -ForegroundColor DarkGreen "   PS> .\scripts\update-product-version.ps1 0 9 0"
    Write-Host
}