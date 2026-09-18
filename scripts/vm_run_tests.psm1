# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param(
    [Parameter(Mandatory = $false)][bool] $ExecuteOnHost = $false,
    [Parameter(Mandatory = $false)][bool] $ExecuteOnVM = $false,
    [Parameter(Mandatory = $false)][bool] $VMIsRemote = $false,
    [Parameter(Mandatory = $false)][string] $VMName = "",
    [Parameter(Mandatory = $true)][string] $WorkingDirectory,
    [Parameter(Mandatory = $true)][string] $LogFileName,
    [Parameter(Mandatory = $false)][string] $TestMode = "CI/CD",
    [Parameter(Mandatory = $false)][string[]] $Options = @("None"),
    [Parameter(Mandatory = $false)][int] $TestHangTimeout = (30 * 60),
    [Parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
    [Parameter(Mandatory = $false)][bool] $GranularTracing = $false,
    [Parameter(Mandatory = $false)][bool] $RunXdpTests = $false
)

if ($ExecuteOnVM -and [string]::IsNullOrWhiteSpace($VMName)) {
    throw "VMName is required when ExecuteOnVM is true."
}

Import-Module "$PSScriptRoot\common.psm1" -Force -ArgumentList $LogFileName -WarningAction SilentlyContinue

function Invoke-OnHostOrVM
{
    param(
        [Parameter(Mandatory = $true)][ScriptBlock] $ScriptBlock,
        [Parameter(Mandatory = $false)][object[]] $ArgumentList = @()
    )

    if ($script:ExecuteOnHost) {
        & $ScriptBlock @ArgumentList
        return
    }

    if (-not $script:ExecuteOnVM) {
        throw "Either ExecuteOnHost or ExecuteOnVM must be true."
    }

    $credential = Get-VMCredential -Username "Administrator" -VMIsRemote $script:VMIsRemote
    Invoke-CommandOnVM `
        -VMName $script:VMName `
        -VMIsRemote $script:VMIsRemote `
        -Credential $credential `
        -ScriptBlock $ScriptBlock `
        -ArgumentList $ArgumentList
}

function Run-KernelTests
{
    $scriptBlock = {
        param($WorkingDirectory, $LogFileName, $Options, $TestHangTimeout, $UserModeDumpFolder)
        Import-Module "$WorkingDirectory\common.psm1" -Force -ArgumentList $LogFileName -WarningAction SilentlyContinue
        Import-Module "$WorkingDirectory\run_driver_tests.psm1" `
            -Force `
            -ArgumentList $WorkingDirectory, $LogFileName, $TestHangTimeout, $UserModeDumpFolder `
            -WarningAction SilentlyContinue
        Invoke-CICDTests -Suites $Options
    }

    Invoke-OnHostOrVM `
        -ScriptBlock $scriptBlock `
        -ArgumentList @(
            $script:WorkingDirectory,
            $script:LogFileName,
            $script:Options,
            $script:TestHangTimeout,
            $script:UserModeDumpFolder)
}

function Stop-eBPFComponents
{
    param([Parameter(Mandatory = $false)][bool] $GranularTracing = $false)

    $scriptBlock = {
        param($WorkingDirectory, $LogFileName, $GranularTracing)
        Import-Module "$WorkingDirectory\common.psm1" -Force -ArgumentList $LogFileName -WarningAction SilentlyContinue
        Import-Module "$WorkingDirectory\install_ebpf.psm1" `
            -Force `
            -ArgumentList $WorkingDirectory, $LogFileName `
            -WarningAction SilentlyContinue
        Stop-eBPFServiceAndDrivers -GranularTracing $GranularTracing
    }

    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList @($script:WorkingDirectory, $script:LogFileName, $GranularTracing)
}

function Generate-KernelDumpOnVM
{
    $scriptBlock = {
        param($WorkingDirectory, $LogFileName)
        Import-Module "$WorkingDirectory\common.psm1" -Force -ArgumentList $LogFileName -WarningAction SilentlyContinue
        Import-Module "$WorkingDirectory\run_driver_tests.psm1" `
            -Force `
            -ArgumentList $WorkingDirectory, $LogFileName `
            -WarningAction SilentlyContinue
        Generate-KernelDump
    }

    Invoke-OnHostOrVM -ScriptBlock $scriptBlock -ArgumentList @($script:WorkingDirectory, $script:LogFileName)
}
