# Contributing to eBPF for Windows

We'd love your help with eBPF for Windows! Here are our contribution guidelines.

- [Code of Conduct](#code-of-conduct)
- [Bugs](#bugs)
- [New Features](#new-features)
- [Building the code](#building-the-code)
- [Testing the code](#testing-the-code)
- [Contributor License Agreement](#contributor-license-agreement)
- [Contributing Code](#contributing-code)
  - [Tests](#tests)

 ## Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Microsoft Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with additional questions or comments.

## Bugs

### Did you find a bug?

First, **ensure the bug was not already reported** by searching on GitHub under
[Issues](https://github.com/microsoft/ebpf-for-windows/issues).

If you found a non-security related bug, you can help us by
[submitting a GitHub Issue](https://github.com/microsoft/ebpf-for-windows/issues/new).
The best bug reports provide a detailed description of the issue and step-by-step instructions
for reliably reproducing the issue.

We will aim to triage issues in weekly triage meetings. In case we are unable to repro the issue, we will request more information from you, the filer.
There will be a waiting period of 2 weeks for the requested information and if there is no response, the issue will be closed. If this happens, please reopen the issue if you do get a repro and collect the requested information.

However, in the best case, we would love it if you can submit a Pull Request with a fix.

If you found a security issue, please **do not open a GitHub Issue**, and instead follow
[these instructions](docs/SECURITY.md).

### Did you write a patch that fixes a bug?

Fork the repo and make your changes.
Then open a new GitHub pull request with the patch.

* Ensure the PR description clearly describes the problem and solution.
Include the relevant issue number if applicable.

* Before submitting, please read the [Development Guide](docs/DevelopmentGuide.md)
to know more about coding conventions.

## New Features

You can request a new feature by [submitting a GitHub Issue](https://github.com/microsoft/ebpf-for-windows/issues/new).

If you would like to implement a new feature, please first
[submit a GitHub Issue](https://github.com/microsoft/ebpf-for-windows/issues/new) and
communicate your proposal so that the community can review and provide feedback. Getting
early feedback will help ensure your implementation work is accepted by the community.
This will also allow us to better coordinate our efforts and minimize duplicated effort.

## Building the code

To build locally, ensure your environment is set up:

1. Install Visual Studio 2022 with at least the "Desktop development with C++" and ".NET desktop development" workloads
1. Install the .NET 8 SDK from https://dotnet.microsoft.com/en-us/download/dotnet/8.0
1. Install the Windows SDK 10.0.22621.0 with `winget install Microsoft.WindowsSDK.10.0.22621`
1. Install the Windows DDK 10.0.22621.0 with `winget install Microsoft.WindowsWDK.10.0.22621`

Then do one-time repo setup:

1. Open a Visual Studio 2022 Developer Command Prompt
1. cd `<root of your clone>`
1. `powershell -file scripts\initialize_repo.ps1`

Then you can build normally in Visual Studio:

1. Open `ntosebpfext.sln` in Visual Studio.  You may want to run VS as admin if you want to debug in VS.

## Testing the code

### Unit tests

Run the unit tests by going to the binaries output folder (ex: `x64\Debug`) and running `ntosebpfext_unit.exe -d yes`

### E2E tests

The end-to-end tests use a tool called `process_monitor` to take data from the `ntosebpfext` extension and place it in a ring buffer that is visible from user-mode (this happens in `process_monitor.sys`).  Then the `process_monitor.exe` user-mode process prints the events it sees to the console.  The `process_monitor.Tests` project contains MSTest tests that exercise the `process_monitor` code with an MSTest head instead of console output.

To run E2E tests you'll need to install eBPF for Windows and the ntosebpfext extension driver locally.

Do the following once:
1. Open a command prompt as admin
1. `cd <your local clone root>`
1. `cd x64\Debug\bin\process_monitor.Tests\win-x64`
1. `powershell -file .\Install-eBpfForWindows.ps1 0.16.0`
1. `powershell -file .\Setup-ProcessMonitorTests.ps1`

Then do this each time you want to re-run the tests:
1. `cd <your local clone root>`
1. `cd tests\process_monitor.Tests`
1. `dotnet test`

#### Running the E2E tests in Visual Studio

You can also run the tests in Visual Studio if it's running as admin.  To do that:

1. Open the Test Explorer window (`Test -> Test Explorer`)
1. You may need to select the gear icon (which could be hidden behind a right arrow in the toolbar), and select the runsettings file (`RunSettings.runsettings` in the repo root). VS should auto-detect this though.
1. You may also want to select the gear icon and choose "run tests after build" to re-run each time you build.
1. Then just run the tests in Test Explorer by clicking the green "play" button.  Or you can right-click a specific test and run/debug it.

### Debugging locally

1. Install eBPF for Windows locally
1. Install `ntosebpfext` locally from an admin command prompt: `sc create ntosebpfext type=kernel start=auto binpath="<your binaries folder>\ntosebpfext\ntosebpfext.sys`
1. Run Visual Studio as admin
1. Choose something like `process_monitor` as the startup project and debug.

Note that when you do this, the `ntosebpfext.sys` driver will be loaded, so if you rebuild the solution, it will fail to build because it can't overwrite the in-use driver.  For this you have a couple of options:

1. `sc stop ntosebpfxt`
1. Build the solution however you like
1. `sc start ntosebpfext`

Or you can just run `scripts\rebuild_ntosebpfext.cmd` which does those 3 steps.

## Contributor License Agreement

You will need to complete a Contributor License Agreement (CLA) for any code submissions.
Briefly, this agreement testifies that you are granting us permission to use the submitted
change according to the terms of the project's license, and that the work being submitted
is under appropriate copyright. You only need to do this once. For more information see
https://cla.opensource.microsoft.com/.

## Contributing Code

For all but the absolute simplest changes, first
[submit a GitHub Issue](https://github.com/microsoft/ebpf-for-windows/issues/new) so that the
community can review and provide feedback. Getting early feedback will help ensure your work
is accepted by the community. This will also allow us to better coordinate our efforts and
minimize duplicated effort.

If you would like to contribute, first identify the scale of what you would like to contribute.
If it is small (grammar/spelling or a bug fix) feel free to start working on a fix. If you are
submitting a feature or substantial code contribution, please discuss it with the maintainers and
ensure it follows the product roadmap. You might also read these two blogs posts on contributing
code: [Open Source Contribution Etiquette](http://tirania.org/blog/archive/2010/Dec-31.html) by Miguel de Icaza and
[Don't "Push" Your Pull Requests](https://www.igvita.com/2011/12/19/dont-push-your-pull-requests/) by Ilya Grigorik.
All code submissions will be rigorously [reviewed](docs/Governance.md) and tested by the maintainers, and only those that meet
the bar for both quality and design/roadmap appropriateness will be merged into the source.

For all new Pull Requests the following rules apply:
- Existing tests should continue to pass.
- [Tests](docs/AutomatedTests.md) need to be provided for every bug/feature that is completed.
- Documentation needs to be provided for every feature that is end-user visible.
