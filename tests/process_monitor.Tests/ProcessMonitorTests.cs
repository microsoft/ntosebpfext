// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using process_monitor.Library;

namespace process_monitor.Tests;

[DoNotParallelize] // These tests are testing process creation and destroy events, running them in parallel makes things noisy.  They're fast anyway.
[TestClass]
public class ProcessMonitorTests
{
    public static ILoggerFactory LoggerFactory { get; set; } = NullLoggerFactory.Instance;

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    // To pin the driver in memory for the duration of the tests, we load it once here, then each test can have its own ProcessMonitor instance,
    // but we won't attempt to unload and reload the driver which is currently nondeterministic in timing.
    private static ProcessMonitor? _processMonitorToPinDriver;
    [ClassInitialize]
#pragma warning disable IDE0060 // Remove unused parameter - this parameter is required to be present by MSTest
    public static void ClassInitialize(TestContext context)
#pragma warning restore IDE0060 // Remove unused parameter
    {
        LoggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Debug);
            _ = builder.AddSimpleConsole(options => options.SingleLine = true);
        });

        _processMonitorToPinDriver = new ProcessMonitor(LoggerFactory.CreateLogger<ProcessMonitor>());
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        _processMonitorToPinDriver?.Dispose();
        _processMonitorToPinDriver = null;
    }

    [TestMethod]
    public async Task ProcessExitCodesWork()
    {
        var expectedCreatingThreadId = GetCurrentThreadId();
        (var createdArgs, var destroyedArgs) = await RunProcessAndWaitForEventsAsync("cmd.exe", "/c exit 456");

        // The parent should be our own process
        Assert.AreEqual((uint)Environment.ProcessId, createdArgs.ParentProcessId);
        Assert.AreEqual((uint)Environment.ProcessId, createdArgs.CreatingProcessId);
        Assert.AreEqual(expectedCreatingThreadId, createdArgs.CreatingThreadId);

        Assert.AreEqual(createdArgs.ImageFileName, destroyedArgs.ImageFileName);
        Assert.AreEqual(createdArgs.CommandLine, destroyedArgs.CommandLine);
        Assert.AreEqual(456u, destroyedArgs.ExitCode);
        Assert.IsTrue(destroyedArgs.ExitTime > createdArgs.CreateTime);
    }

    [TestMethod]
    public async Task ProcessCreateAndExitTimesWork()
    {
        var expectedCreatingThreadId = GetCurrentThreadId();
        (var createdArgs, var destroyedArgs) = await RunProcessAndWaitForEventsAsync("powershell.exe", "-noprofile -ex bypass -c sleep -milliseconds 3000");

        // The parent should be our own process
        Assert.AreEqual((uint)Environment.ProcessId, createdArgs.ParentProcessId);
        Assert.AreEqual((uint)Environment.ProcessId, createdArgs.CreatingProcessId);
        Assert.AreEqual(expectedCreatingThreadId, createdArgs.CreatingThreadId);

        Assert.AreEqual(createdArgs.ImageFileName, destroyedArgs.ImageFileName);
        Assert.AreEqual(createdArgs.CommandLine, destroyedArgs.CommandLine);
        Assert.AreEqual(0u, destroyedArgs.ExitCode);
        // "timeout 3" should ensure we take at least 3 seconds to exit.
        // So we'll check that we're > 3 but below some resonable threshold of imprecision beyond that.
        Assert.IsTrue(destroyedArgs.ExitTime - createdArgs.CreateTime > TimeSpan.FromSeconds(3), $"ExitTime - CreateTime is not >3 seconds, it is {destroyedArgs.ExitTime - createdArgs.CreateTime}.  CreateTime={createdArgs.CreateTime:O}, ExitTime={destroyedArgs.ExitTime:O}");
        Assert.IsTrue(destroyedArgs.ExitTime - createdArgs.CreateTime < TimeSpan.FromSeconds(4));
    }

    [TestMethod]
    public async Task VeryLongCommandLinesArriveIntact()
    {
        var expectedCreatingThreadId = GetCurrentThreadId();
        var longArgs = new string('a', 5000) + 'b';
        (var createdArgs, var destroyedArgs) = await RunProcessAndWaitForEventsAsync("cmd.exe", $"/c echo {longArgs}");

        // The parent should be our own process
        Assert.AreEqual((uint)Environment.ProcessId, createdArgs.ParentProcessId);
        Assert.AreEqual((uint)Environment.ProcessId, createdArgs.CreatingProcessId);
        Assert.AreEqual(expectedCreatingThreadId, createdArgs.CreatingThreadId);
        Assert.AreEqual($"\"cmd.exe\" /c echo {longArgs}", createdArgs.CommandLine);

        Assert.AreEqual(createdArgs.ImageFileName, destroyedArgs.ImageFileName);
        Assert.AreEqual(createdArgs.CommandLine, destroyedArgs.CommandLine);
        Assert.AreEqual(0u, destroyedArgs.ExitCode);
    }

    private static async Task<(ProcessCreatedEventArgs created, ProcessDestroyedEventArgs destroyed)>
        RunProcessAndWaitForEventsAsync(string exeName, string arguments)
    {
        using var pm = new ProcessMonitor(LoggerFactory.CreateLogger<ProcessMonitor>());

        var processDestoryHappened = new ManualResetEvent(false);
        var testPID = 0u;
        ProcessCreatedEventArgs createdArgs = default;
        ProcessDestroyedEventArgs destroyedArgs = default;

        pm.ProcessCreated += (sender, e) =>
        {
            if (e.ImageFileName.EndsWith(exeName, StringComparison.Ordinal) &&
                e.CommandLine.Contains($"\"{exeName}\" {arguments}", StringComparison.Ordinal))
            {
                testPID = e.ProcessId;
                createdArgs = e;
            }
        };

        pm.ProcessDestroyed += (sender, e) =>
        {
            if (e.ProcessId == testPID)
            {
                destroyedArgs = e;
                processDestoryHappened.Set();
            }
        };

        {
            using var cmdProcess = Process.Start(exeName, arguments);
            await cmdProcess.WaitForExitAsync();
        }

        Assert.IsTrue(processDestoryHappened.WaitOne(TimeSpan.FromSeconds(10)), "Test never received the process destroy message");

        return (createdArgs, destroyedArgs);
    }
}