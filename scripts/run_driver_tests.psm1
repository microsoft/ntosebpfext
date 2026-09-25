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

function Write-DriverTestOutput
{
    param(
        [Parameter(Mandatory = $true)][string] $StdoutPath,
        [Parameter(Mandatory = $true)][string] $StderrPath
    )

    if (Test-Path $StdoutPath) {
        Get-Content $StdoutPath | Write-Log
    }
    if ((Test-Path $StderrPath) -and (Get-Item $StderrPath).Length -gt 0) {
        Get-Content $StderrPath | Write-Log
    }
}

function Invoke-ExtensionDriverTest
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

    # Cache the process handle so its exit information remains available after termination.
    $handle = $process.Handle

    $exited = $process.WaitForExit($Timeout * 1000)
    if (-not $exited -or -not $process.HasExited) {
        Write-Log "$Name exceeded its timeout. A kernel dump will be requested."
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        if (-not $process.WaitForExit(5000)) {
            Write-Log "Warning: $Name did not exit within 5 seconds after termination was requested."
        }
        Write-DriverTestOutput -StdoutPath $stdoutPath -StderrPath $stderrPath
        throw [System.TimeoutException]::new("$Name timed out after $Timeout seconds.")
    }

    $exitCode = $process.ExitCode
    Write-DriverTestOutput -StdoutPath $stdoutPath -StderrPath $stderrPath

    if ($null -eq $exitCode) {
        throw "$Name completed, but its exit code could not be read."
    }
    if ($exitCode -ne 0) {
        throw "$Name failed with exit code $exitCode."
    }

    Write-Log "$Name passed."
}

function New-TestTuple
{
    param(
        [Parameter(Mandatory = $true)][string] $Suite,
        [Parameter(Mandatory = $true)][string] $Test,
        [Parameter(Mandatory = $false)][string] $Arguments = "-d yes",
        [Parameter(Mandatory = $false)][int] $Timeout = $TestHangTimeout
    )

    [PSCustomObject]@{
        Suite = $Suite
        Test = $Test
        Arguments = $Arguments
        Timeout = $Timeout
    }
}

function Invoke-CICDTests
{
    param([Parameter(Mandatory = $false)][string[]] $Suites = @("None"))

    $testList = @(
        (New-TestTuple -Suite "ntosebpfext" -Test "ntosebpfext_driver_test.exe" -Timeout $TestHangTimeout),
        (New-TestTuple -Suite "neteventebpfext" -Test "neteventebpfext_driver_test.exe" -Timeout $TestHangTimeout)
    )

    $selectedTests = $testList
    if ($Suites -and ($Suites -notcontains "None")) {
        $selectedTests = @($testList | Where-Object { $Suites -contains $_.Suite })
    }
    if ($selectedTests.Count -eq 0) {
        throw "No driver tests matched options: $($Suites -join ', ')."
    }

    foreach ($test in $selectedTests) {
        Invoke-ExtensionDriverTest `
            -Name $test.Test `
            -Arguments $test.Arguments `
            -Timeout $test.Timeout
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
