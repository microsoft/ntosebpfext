# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param(
    [Parameter(Mandatory = $true)][string] $WorkingDirectory,
    [Parameter(Mandatory = $true)][string] $LogFileName
)

Import-Module "$PSScriptRoot\common.psm1" -Force -ArgumentList $LogFileName -WarningAction SilentlyContinue

function Install-eBPFComponents
{
    param(
        [Parameter(Mandatory = $true)][bool] $KmTracing,
        [Parameter(Mandatory = $true)][string] $KmTraceType,
        [Parameter(Mandatory = $false)][bool] $KMDFVerifier = $false,
        [Parameter(Mandatory = $true)][string] $TestMode,
        [Parameter(Mandatory = $false)][switch] $SkipRebootOperations,
        [Parameter(Mandatory = $false)][bool] $GranularTracing = $false
    )

    $msiPath = Join-Path $WorkingDirectory "ebpf-for-windows.msi"
    if (-not (Test-Path $msiPath -PathType Leaf)) {
        throw "Required eBPF for Windows installer was not found at '$msiPath'."
    }

    Write-Log "Installing eBPF for Windows from $msiPath"
    $arguments = @("/i", $msiPath, "ADDLOCAL=ALL", "/qn", "/norestart", "/l*v", "msi-install.log")
    $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) {
        if (Test-Path "msi-install.log") {
            Get-Content "msi-install.log" | Write-Log
        }
        throw "eBPF for Windows installation failed with exit code $($process.ExitCode)."
    }

    if ($process.ExitCode -eq 3010) {
        Write-Log "eBPF for Windows installation requested a reboot; continuing because the package was installed with /norestart."
    }

    if ($KMDFVerifier) {
        Write-Log "The 1ES inner VM image controls driver verifier settings; no additional verifier configuration is applied."
    }

    Write-Log "eBPF for Windows installation completed."
}

function Stop-eBPFServiceAndDrivers
{
    param([Parameter(Mandatory = $false)][bool] $GranularTracing = $false)

    foreach ($serviceName in @("ntosebpfext", "neteventebpfext", "netevent_sim")) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne "Stopped") {
            Write-Log "Stopping leftover test driver service $serviceName"
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        }
    }
}

function Uninstall-eBPFComponents
{
    Write-Log "The inner VM is discarded after the job; eBPF for Windows is not uninstalled explicitly."
}
