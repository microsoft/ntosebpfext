# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param(
    [Parameter(Mandatory = $true)][string] $WorkingDirectory,
    [Parameter(Mandatory = $true)][string] $LogFileName,
    [Parameter(Mandatory = $false)][int] $TestHangTimeout = (30 * 60),
    [Parameter(Mandatory = $false)][string] $UserModeDumpFolder = "C:\Dumps",
    [Parameter(Mandatory = $false)][bool] $GranularTracing = $false
)

Import-Module "$PSScriptRoot\common.psm1" -Force -ArgumentList $LogFileName -WarningAction SilentlyContinue

function Invoke-NtosDriverTest
{
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $false)][string] $Arguments = "-d yes",
        [Parameter(Mandatory = $false)][int] $Timeout = $TestHangTimeout
    )

    $testPath = Join-Path $WorkingDirectory $Name
    if (-not (Test-Path $testPath -PathType Leaf)) {
        throw "Driver test executable was not found at '$testPath'."
    }

    $testLogs = Join-Path $WorkingDirectory "TestLogs"
    New-Item -Path $testLogs -ItemType Directory -Force | Out-Null
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Name)
    $stdoutPath = Join-Path $testLogs "$baseName.stdout.log"
    $stderrPath = Join-Path $testLogs "$baseName.stderr.log"

    Write-Log "Executing $Name $Arguments with timeout $Timeout seconds."
    $process = Start-Process `
        -FilePath $testPath `
        -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -PassThru

    if (-not $process.WaitForExit($Timeout * 1000)) {
        Write-Log "$Name exceeded its timeout. A kernel dump will be requested."
        throw [System.TimeoutException]::new("$Name timed out after $Timeout seconds.")
    }

    if (Test-Path $stdoutPath) {
        Get-Content $stdoutPath | Write-Log
    }
    if ((Test-Path $stderrPath) -and (Get-Item $stderrPath).Length -gt 0) {
        Get-Content $stderrPath | Write-Log
    }

    if ($process.ExitCode -ne 0) {
        throw "$Name failed with exit code $($process.ExitCode)."
    }

    Write-Log "$Name passed."
}

function Invoke-NtosDriverTests
{
    param([Parameter(Mandatory = $true)][object[]] $Tests)

    foreach ($test in $Tests) {
        $arguments = if ($null -ne $test.Arguments) { [string]$test.Arguments } else { "-d yes" }
        $timeout = if ($null -ne $test.Timeout) { [int]$test.Timeout } else { $TestHangTimeout }
        Invoke-NtosDriverTest -Name ([string]$test.Name) -Arguments $arguments -Timeout $timeout
    }
}

function Generate-KernelDump
{
    $notMyFault = Get-ChildItem -Path $WorkingDirectory -Recurse -Filter "NotMyFault64.exe" |
        Select-Object -First 1
    if (-not $notMyFault) {
        throw "NotMyFault64.exe was not found under '$WorkingDirectory'."
    }

    Write-Log "Generating a kernel dump with $($notMyFault.FullName)."
    Start-Process -FilePath $notMyFault.FullName -ArgumentList "/crash" -NoNewWindow
}
