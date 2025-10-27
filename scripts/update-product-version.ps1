# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ($majorVersion, $minorVersion, $revisionNumber)

# Check if the version number is in the format X.Y.Z
if ("$majorVersion.$minorVersion.$revisionNumber" -match '^\d+\.\d+\.\d+$') {

    if (Test-Path -Path ".\ntosebpfext.sln") {
        # Set the new version number in the Directory.Build.props file.
        $ntosebpfext_build_prop_file = "$PSScriptRoot\..\Directory.Build.props"
        Write-Host -ForegroundColor DarkGreen "Updating the version number in the '$ntosebpfext_build_prop_file' file..."
        # Replace <eBPFExtensionsVersionMajor>0</eBPFExtensionsVersionMajor> with <eBPFExtensionsVersionMajor>$majorVersion</eBPFExtensionsVersionMajor>
        $newcontent = (Get-Content $ntosebpfext_build_prop_file -Raw -Encoding UTF8) `
                        -replace '(?<=<eBPFExtensionsVersionMajor>)\d+', $majorVersion `
                        -replace '(?<=<eBPFExtensionsVersionMinor>)\d+', $minorVersion `
                        -replace '(?<=<eBPFExtensionsVersionRevision>)\d+', $revisionNumber
        $newcontent | Set-Content $ntosebpfext_build_prop_file -NoNewline
        Write-Host -ForegroundColor DarkGreen "Version number updated to '$majorVersion.$minorVersion.$revisionNumber' in $ntosebpfext_build_prop_file"

        # Set the new version number in the ebpf_ext_version.h file.
        $ntosebpfext_version_file = "$PSScriptRoot\..\resource\ebpf_ext_version.h"
        # Replace #define EBPF_VERSION_MAJOR 0 with #define EBPF_VERSION_MAJOR $majorVersion
        $newcontent = (Get-Content $ntosebpfext_version_file -Raw -Encoding UTF8) `
                        -replace '(?<=#define EBPF_VERSION_MAJOR )\d+', $majorVersion `
                        -replace '(?<=#define EBPF_VERSION_MINOR )\d+', $minorVersion `
                        -replace '(?<=#define EBPF_VERSION_REVISION )\d+', $revisionNumber
        $newcontent | Set-Content $ntosebpfext_version_file -NoNewline
        Write-Host -ForegroundColor DarkGreen "Version number updated to '$majorVersion.$minorVersion.$revisionNumber' in $ntosebpfext_version_file"

        # Set the new version number in the version.json file.
        $version_json_file = "$PSScriptRoot\..\version.json"
        Write-Host -ForegroundColor DarkGreen "Updating the version number in the '$version_json_file' file..."
        $versionJson = [ordered]@{
            major = [int]$majorVersion
            minor = [int]$minorVersion
            patch = [int]$revisionNumber
        }
        $versionJson | ConvertTo-Json | Set-Content $version_json_file -Encoding UTF8
        Write-Host -ForegroundColor DarkGreen "Version number updated to '$majorVersion.$minorVersion.$revisionNumber' in $version_json_file"

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