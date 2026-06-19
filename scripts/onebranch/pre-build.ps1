# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

$OneBranchArch = $env:ONEBRANCH_ARCH
$OneBranchConfig = $env:ONEBRANCH_CONFIG
$OutputBinFolder = ".\build\bin\$($OneBranchArch)_$($OneBranchConfig)"

# Get the path where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change the parent directory for the script directory
Set-Location $scriptPath\..\..

try {
    Copy-Item .\scripts\onebranch\nuget.config .\nuget.config
    .\scripts\initialize_repo.ps1

    # Install LLVM tools (clang with BPF target support) for compiling eBPF programs.
    Write-Host "Installing LLVM tools..."
    nuget install llvm.tools -OutputDirectory packages -version 19.1.4-34 -ExcludeVersion
    if ($LASTEXITCODE -ne 0) { throw "Failed to install llvm.tools" }
    nuget install clang.headers -OutputDirectory packages -version 19.1.4-34 -ExcludeVersion
    if ($LASTEXITCODE -ne 0) { throw "Failed to install clang.headers" }

    # Add LLVM tools to PATH so clang is available for BPF compilation.
    $llvmPath = Join-Path (Get-Location) "packages\llvm.tools"
    $env:Path = "$llvmPath;$env:Path"
    Write-Host "##vso[task.prependpath]$llvmPath"
    Write-Host "LLVM tools installed. Clang version:"
    clang --version

    # Place clang builtin headers where the clang resource directory expects them.
    # clang --print-resource-dir resolves to <llvm.tools>\lib\clang\<major>, but the
    # llvm.tools NuGet package does not ship the builtin headers (stdbool.h, etc.).
    # The clang.headers NuGet package provides them at packages\clang.headers\include\.
    # Copy them to the resource directory so clang can find them automatically.
    $clangResourceDir = & "$llvmPath\clang.exe" --print-resource-dir 2>&1
    $clangResourceInclude = Join-Path $clangResourceDir "include"
    if (-not (Test-Path $clangResourceInclude)) {
        New-Item -ItemType Directory -Path $clangResourceInclude -Force | Out-Null
    }
    $headersSource = Join-Path (Get-Location) "packages\clang.headers\include"
    Write-Host "Copying clang headers from '$headersSource' to '$clangResourceInclude'..."
    Copy-Item -Path "$headersSource\*" -Destination $clangResourceInclude -Recurse -Force
    Write-Host "Clang builtin headers installed."

    # Copy any scripts that will be packaged into the output folder
    $OutputScriptsFolder = Join-Path $OutputBinFolder "scripts"
    if (-not (Test-Path -Path $OutputScriptsFolder)) {
        New-Item -ItemType Directory -Path $OutputScriptsFolder -Force
    }
    Copy-Item .\scripts\Install-Extension.ps1 $OutputScriptsFolder
} catch {
    throw "Failed to initialize the repository."
}

Get-ChildItem -Path ./external -Filter *.dll -Recurse | Remove-Item
