// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using process_monitor.Library;

namespace process_monitor.Tests;

[DoNotParallelize] // These tests are testing process creation and destroy events, running them in parallel makes things noisy.  They're fast anyway.
[TestClass]
public class ProcessMonitorTests
{
    public static ILoggerFactory LoggerFactory { get; set; } = NullLoggerFactory.Instance;

    // The child process in ProcessCreateAndExitTimesWork sleeps for this long, so the kernel-reported
    // lifetime must be at least this.
    private static readonly TimeSpan ChildProcessSleepDuration = TimeSpan.FromSeconds(3);

    // The create/exit delta covers the whole process lifetime (interpreter startup, assembly load/JIT,
    // the sleep, then shutdown), not just the sleep. CI runners are frequently oversubscribed, so this
    // upper bound only needs to be loose enough to catch a grossly wrong timestamp (e.g. wrong epoch,
    // wrong units, or a swapped create/exit time) without failing on ordinary scheduling delays.
    private static readonly TimeSpan ChildProcessLifetimeUpperBound = TimeSpan.FromSeconds(60);

    // Upper bound on how long we wait for the kernel's process events to be delivered. Delivery is
    // asynchronous via the ring buffer, so on an oversubscribed CI runner this can lag well behind the
    // process itself.
    private static readonly TimeSpan EventDeliveryTimeout = TimeSpan.FromSeconds(60);

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
        using var identity1 = WindowsIdentity.GetCurrent();
        var expectedSid1 = identity1.User?.Value;
        Assert.IsFalse(string.IsNullOrEmpty(expectedSid1), "Current user's SID should be available for SID validation");
        Assert.IsFalse(string.IsNullOrEmpty(createdArgs.TokenSid), "TokenSid should be non-empty for process creation events");
        Assert.AreEqual(expectedSid1, createdArgs.TokenSid, "TokenSid should match the current user's SID");
        Assert.IsFalse(string.IsNullOrEmpty(createdArgs.AccountName), "AccountName should be non-empty for process creation events");
        Assert.IsFalse(string.IsNullOrEmpty(createdArgs.AccountDomain), "AccountDomain should be non-empty for process creation events");

        Assert.AreEqual(createdArgs.ImageFileName, destroyedArgs.ImageFileName);
        Assert.AreEqual(createdArgs.CommandLine, destroyedArgs.CommandLine);
        Assert.AreEqual(456u, destroyedArgs.ExitCode);
        Assert.IsTrue(destroyedArgs.ExitTime > createdArgs.CreateTime);
    }

    [TestMethod]
    public async Task ProcessCreateAndExitTimesWork()
    {
        var expectedCreatingThreadId = GetCurrentThreadId();
        (var createdArgs, var destroyedArgs) = await RunProcessAndWaitForEventsAsync("powershell.exe", $"-noprofile -ex bypass -c sleep -milliseconds {(int)ChildProcessSleepDuration.TotalMilliseconds}");

        // The parent should be our own process
        Assert.AreEqual((uint)Environment.ProcessId, createdArgs.ParentProcessId);
        Assert.AreEqual((uint)Environment.ProcessId, createdArgs.CreatingProcessId);
        Assert.AreEqual(expectedCreatingThreadId, createdArgs.CreatingThreadId);
        using var identity2 = WindowsIdentity.GetCurrent();
        var expectedSid2 = identity2.User?.Value;
        Assert.IsFalse(string.IsNullOrEmpty(expectedSid2), "Current user's SID should be available for SID validation");
        Assert.IsFalse(string.IsNullOrEmpty(createdArgs.TokenSid), "TokenSid should be non-empty for process creation events");
        Assert.AreEqual(expectedSid2, createdArgs.TokenSid, "TokenSid should match the current user's SID");
        Assert.IsFalse(string.IsNullOrEmpty(createdArgs.AccountName), "AccountName should be non-empty for process creation events");
        Assert.IsFalse(string.IsNullOrEmpty(createdArgs.AccountDomain), "AccountDomain should be non-empty for process creation events");

        Assert.AreEqual(createdArgs.ImageFileName, destroyedArgs.ImageFileName);
        Assert.AreEqual(createdArgs.CommandLine, destroyedArgs.CommandLine);
        Assert.AreEqual(0u, destroyedArgs.ExitCode);
        // The child sleeps for ChildProcessSleepDuration, so its kernel-reported lifetime must be at least
        // that long. This lower bound is the assertion with real product value: it proves CreateTime and
        // ExitTime are distinct, correctly ordered, and in sensible units.
        var lifetime = destroyedArgs.ExitTime - createdArgs.CreateTime;
        Assert.IsTrue(
            lifetime > ChildProcessSleepDuration,
            $"ExitTime - CreateTime is not >{ChildProcessSleepDuration.TotalSeconds} seconds, it is {lifetime}.  CreateTime={createdArgs.CreateTime:O}, ExitTime={destroyedArgs.ExitTime:O}");
        Assert.IsTrue(
            lifetime < ChildProcessLifetimeUpperBound,
            $"ExitTime - CreateTime is not <{ChildProcessLifetimeUpperBound.TotalSeconds} seconds, it is {lifetime}.  CreateTime={createdArgs.CreateTime:O}, ExitTime={destroyedArgs.ExitTime:O}");
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
        using var identity3 = WindowsIdentity.GetCurrent();
        var expectedSid3 = identity3.User?.Value;
        Assert.IsFalse(string.IsNullOrEmpty(expectedSid3), "Current user's SID should be available for SID validation");
        Assert.IsFalse(string.IsNullOrEmpty(createdArgs.TokenSid), "TokenSid should be non-empty for process creation events");
        Assert.AreEqual(expectedSid3, createdArgs.TokenSid, "TokenSid should match the current user's SID");
        Assert.AreEqual(createdArgs.ImageFileName, destroyedArgs.ImageFileName);
        Assert.AreEqual(createdArgs.CommandLine, destroyedArgs.CommandLine);
        Assert.AreEqual(0u, destroyedArgs.ExitCode);
    }

    private static async Task<(ProcessCreatedEventArgs created, ProcessDestroyedEventArgs destroyed)>
        RunProcessAndWaitForEventsAsync(string exeName, string arguments)
    {
        using var pm = new ProcessMonitor(LoggerFactory.CreateLogger<ProcessMonitor>());

        using var processDestoryHappened = new ManualResetEvent(false);
        using var processCreateObserved = new ManualResetEvent(false);
        var testPID = 0u;
        ProcessCreatedEventArgs createdArgs = default;
        ProcessDestroyedEventArgs destroyedArgs = default;

        pm.ProcessCreated += (sender, e) =>
        {
            if (e.ImageFileName.EndsWith(exeName, StringComparison.Ordinal) &&
                e.CommandLine.Contains($"\"{exeName}\" {arguments}", StringComparison.Ordinal))
            {
                createdArgs = e;
                // Publish the PID last so the destroy handler never observes a PID without its create args.
                Volatile.Write(ref testPID, e.ProcessId);
                processCreateObserved.Set();
            }
        };

        pm.ProcessDestroyed += (sender, e) =>
        {
            var expectedPid = Volatile.Read(ref testPID);
            if (expectedPid != 0 && e.ProcessId == expectedPid)
            {
                destroyedArgs = e;
                processDestoryHappened.Set();
            }
        };

        uint startedPid;
        {
            using var cmdProcess = Process.Start(exeName, arguments);
            startedPid = (uint)cmdProcess.Id;
            await cmdProcess.WaitForExitAsync();
        }

        // Distinguish "we never saw the create event" from "we saw create but never saw destroy".
        Assert.IsTrue(
            processCreateObserved.WaitOne(EventDeliveryTimeout),
            $"Test never received the process create message for {exeName} (PID {startedPid}) within {EventDeliveryTimeout.TotalSeconds} seconds");

        Assert.IsTrue(
            processDestoryHappened.WaitOne(EventDeliveryTimeout),
            $"Test never received the process destroy message for {exeName} (PID {startedPid}) within {EventDeliveryTimeout.TotalSeconds} seconds");

        return (createdArgs, destroyedArgs);
    }
}