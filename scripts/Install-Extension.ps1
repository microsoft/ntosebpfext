<#
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

.SYNOPSIS
This script provides helpers to install or uninstall ebpf extensions.

.PARAMETER Extension
    Specifies the extension to install. This MUST be one of ("neteventebpfext", "ntosebpfext").

.PARAMETER Action
    Specifies the action to take. This MUST be either "Install" or "Uninstall".

.PARAMETER BinaryDirectory
    Specifies the directory containing the necessary binaries().
    This MUST be the full path to the directory. By default, the current directory is used.

.EXAMPLE
    Install_Extension.ps1 -Action Install

.EXAMPLE
    Install_Extension.ps1 -Action Uninstall -Extension "neteventebpfext" 

.EXAMPLE
    Install_Extension.ps1 -Action Install -BinaryDirectory "C:\binaries"
#>

param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("Install", "Uninstall")]
    [string]$Action,
    [Parameter(Mandatory=$true)]
    [ValidateSet("neteventebpfext", "ntosebpfext")]
    [string]$Extension,
    [Parameter(Mandatory=$false)]
    [string]$BinaryDirectory = (Get-Location).Path
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

<#
.SYNOPSIS
Stops and deletes a service.

.PARAMETER ServiceName
The name of the service to cleanup.

.EXAMPLE
Clear-Service -ServiceName "neteventebpfext"
#>
function Clear-Service(
    [Parameter(Mandatory=$true)]
    [string]$ServiceName
) {
    # Wait for the service to stop.
    $StopSuccess = $false
    try {
        Stop-Service $ServiceName
        for ($i = 0; $i -lt 100; $i++) {
            if (-not (Get-Service $ServiceName -ErrorAction Ignore) -or
                (Get-Service $ServiceName).Status -eq "Stopped") {
                $StopSuccess = $true
                break;
            }
            Start-Sleep -Milliseconds 100
        }
        if (!$StopSuccess) {
            Write-Verbose "$ServiceName failed to stop"
        }
    } catch {
        Write-Verbose "Exception while waiting for $ServiceName to stop"
    }

    # Delete the service.
    if (Get-Service $ServiceName -ErrorAction Ignore) {
        try { sc.exe delete $ServiceName > $null }
        catch { Write-Verbose "'sc.exe delete $ServiceName' threw exception!" }

        # Wait for the service to be deleted.
        $DeleteSuccess = $false
        for ($i = 0; $i -lt 10; $i++) {
            if (-not (Get-Service $ServiceName -ErrorAction Ignore)) {
                $DeleteSuccess = $true
                break;
            }
            Start-Sleep -Milliseconds 10
        }
        if (!$DeleteSuccess) {
            Write-Verbose "Failed to clean up $ServiceName!"
        }
    }
}

<#
.SYNOPSIS
Starts a service with retry attempts.

.PARAMETER ServiceName
The name of the service to start.

.EXAMPLE
Start-Service-With-Retry -ServiceName "neteventebpfext"
#>
function Start-Service-With-Retry(
    [Parameter(Mandatory=$true)]
    [string]$ServiceName
) {
    Write-Verbose "Start-Service $ServiceName"
    $StartSuccess = $false

    for ($i=0; $i -lt 100; $i++) {
        try {
            Start-Sleep -Milliseconds 10
            Start-Service $ServiceName
            $StartSuccess = $true
            break
        } catch { }
    }

    if ($StartSuccess -eq $false) {
        Write-Error "Failed to start $ServiceName"
    }
}

<#
.SYNOPSIS
Installs a service and starts it.

.PARAMETER ServiceName
The name of the service to install.

.PARAMETER BinaryPath
The path to the binary to install as a service. This MUST be the full path.

.EXAMPLE
Install-Service -ServiceName "neteventebpfext" -BinaryPath "C:\neteventebpfext.sys"
#>
function Install-Service(
    [Parameter(Mandatory=$true)]
    [string]$ServiceName,
    [Parameter(Mandatory=$true)]
    [string]$BinaryPath
)
{
    # Cleanup service if it already exists.
    $ServiceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($ServiceExists) {
        Write-Verbose "$ServiceName already exists. Attempting to cleanup the service first."
        Clear-Service -ServiceName $ServiceName
    }

    # Install the service.
    sc.exe create $ServiceName type= kernel binpath= $BinaryPath start= system | Write-Verbose
    if ($LastExitCode) { Write-Error "Failed to install driver" }

    # Start the service.
    Start-Service-With-Retry $ServiceName

    Write-Verbose "$ServiceName install complete!"
}

<#
.SYNOPSIS
This function installs the service and updates the eBPF store.

.PARAMETER ServiceName
The name of the service to install.

.PARAMETER BinaryPath
The path to the binary to install as a service. This MUST be the full path.

.PARAMETER BpfExportPath
The path to the bpf export exe.
#>
function Install-Extension(
    [Parameter(Mandatory=$true)]
    [string]$ServiceName,
    [Parameter(Mandatory=$true)]
    [string]$BinaryPath,
    [Parameter(Mandatory=$true)]
    [string]$BpfExportPath
) {
    Write-Verbose "Installing $ServiceName at $ExtPath"
    Install-Service -ServiceName $ServiceName -BinaryPath $ExtPath

    Write-Verbose "Updating eBPF store"
    & $BpfExportPath | Write-Verbose
    if ($LastExitCode) { Write-Error "Failed to update eBPF store" }

    Write-Verbose "Installation Complete!"
}


<#
.SYNOPSIS
This function uninstalls the service and clears the eBPF store.
.PARAMETER ServiceName
The name of the service to install.

.PARAMETER BpfExportPath
The path to the bpf export exe.
#>
function Uninstall-Extension(
    [Parameter(Mandatory=$true)]
    [string]$ServiceName,
    [Parameter(Mandatory=$true)]
    [string]$BpfExportPath
) {
    # Stop and delete the service.
    Clear-Service -ServiceName $ServiceName

    Write-Verbose "Clearing the eBPF store"
    & $BpfExportPath --clear | Write-Verbose
    if ($LastExitCode) { Write-Verbose "Failed to clear eBPF store" }

    Write-Verbose "Uninstall complete!"
}

<#
.SYNOPSIS
This function sets up paths and names needed for installing/uninstalling neteventebpfext
#>
function Set-Path-Neteventebpfext {
    $script:ExtPath =  Join-Path -Path $BinaryDirectory -ChildPath "neteventebpfext.sys"
    $script:ServiceName = "neteventebpfext"
    $script:BpfExportPath =  Join-Path -Path $BinaryDirectory -ChildPath "netevent_ebpf_ext_export_program_info.exe"
}

<#
.SYNOPSIS
This function sets up paths and names needed for installing/uninstalling ntosebpfext
#>
function Set-Path-Ntosebpfext {
    $script:ExtPath =  Join-Path -Path $BinaryDirectory -ChildPath "ntosebpfext.sys"
    $script:ServiceName = "ntosebpfext"
    $script:BpfExportPath =  Join-Path -Path $BinaryDirectory -ChildPath "ntos_ebpf_ext_export_program_info.exe"
}

switch($Extension) {
    "neteventebpfext" { Set-Path-Neteventebpfext }
    "ntosebpfext" { Set-Path-Ntosebpfext }
}

if ($Action -eq "Install") {
    Install-Extension -ServiceName $script:ServiceName -BinaryPath $script:ExtPath -BpfExportPath $script:BpfExportPath
} elseif ($Action -eq "Uninstall") {
    Uninstall-Extension -ServiceName $script:ServiceName -BpfExportPath $script:BpfExportPath
}