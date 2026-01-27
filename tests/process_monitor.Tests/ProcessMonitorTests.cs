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

    [TestMethod]
    public unsafe void BpfProgTestRunContextCreateDelete()
    {
        // This test validates that the context_create and context_delete functions are working properly
        // by using bpf_prog_test_run_opts to invoke the program directly with test data.

        var logger = LoggerFactory.CreateLogger<ProcessMonitorTests>();

        // Open and load the BPF program
        IntPtr bpfObject = process_monitor.PInvokes.bpf_object__open("process_monitor.sys");
        Assert.AreNotEqual(IntPtr.Zero, bpfObject, "bpf_object__open failed");

        try
        {
            int loadResult = process_monitor.PInvokes.bpf_object__load(bpfObject);
            Assert.AreEqual(0, loadResult, $"bpf_object__load failed with error code: {loadResult}");

            // Find the ProcessMonitor program
            IntPtr processMonitorProgram = process_monitor.PInvokes.bpf_object__find_program_by_name(bpfObject, "ProcessMonitor");
            Assert.AreNotEqual(IntPtr.Zero, processMonitorProgram, "bpf_object__find_program_by_name failed");

            // Get the program file descriptor
            int programFd = process_monitor.PInvokes.bpf_program__fd(processMonitorProgram);
            Assert.AreNotEqual(-1, programFd, "bpf_program__fd failed");

            // Prepare test command line data (UTF-16 string)
            string testCommandLine = "test.exe -arg1 -arg2";
            byte[] commandLineBytes = System.Text.Encoding.Unicode.GetBytes(testCommandLine);

            // Ensure we have valid data
            Assert.IsTrue(commandLineBytes.Length > 0, "Command line bytes should not be empty");

            fixed (byte* commandLinePtr = commandLineBytes)
            {
                // Calculate end pointer safely within bounds
                byte* commandLineEndPtr = commandLinePtr + commandLineBytes.Length;
                
                // Create input context using the shared structure from PInvokes
                process_monitor.PInvokes.process_md_t ctxIn = new process_monitor.PInvokes.process_md_t
                {
                    command_start = (IntPtr)commandLinePtr,
                    command_end = (IntPtr)commandLineEndPtr,
                    process_id = 1234,
                    parent_process_id = 5678,
                    creating_process_id = 5678,
                    creating_thread_id = 9999,
                    creation_time = (ulong)DateTime.UtcNow.ToFileTimeUtc(),
                    exit_time = 0,
                    process_exit_code = 0,
                    operation = 0 // PROCESS_OPERATION_CREATE
                };

                // Create output context
                process_monitor.PInvokes.process_md_t ctxOut = new process_monitor.PInvokes.process_md_t();

                // Prepare bpf_test_run_opts structure using factory method
                process_monitor.PInvokes.bpf_test_run_opts opts = process_monitor.PInvokes.bpf_test_run_opts.Create();
                opts.repeat = 1;
                opts.ctx_in = &ctxIn;
                opts.ctx_size_in = sizeof(process_monitor.PInvokes.process_md_t);
                opts.ctx_out = &ctxOut;
                opts.ctx_size_out = sizeof(process_monitor.PInvokes.process_md_t);
                // data_in contains the command line data that context_create will point to via command_start/command_end
                opts.data_in = commandLinePtr;
                opts.data_size_in = commandLineBytes.Length;
                opts.data_out = null; // We're not expecting data_out for process monitor
                opts.data_size_out = 0;

                // Execute the program - expect success for valid input
                int result = process_monitor.PInvokes.bpf_prog_test_run_opts(programFd, &opts);
                Assert.AreEqual(0, result, "bpf_prog_test_run_opts should succeed with valid input");

                // Validate output context size
                Assert.AreEqual(sizeof(process_monitor.PInvokes.process_md_t), opts.ctx_size_out, "Output context size should match input");

                logger.LogDebug("SUCCESS: bpf_prog_test_run_opts with valid input succeeded");

                // Negative test case: null context should fail
                opts.ctx_in = null;
                opts.ctx_size_in = 0;

                result = process_monitor.PInvokes.bpf_prog_test_run_opts(programFd, &opts);
                Assert.AreNotEqual(0, result, "bpf_prog_test_run_opts should fail with null context");

                logger.LogDebug("SUCCESS: bpf_prog_test_run_opts correctly rejected null context");

                // Negative test case: context size too small should fail
                byte smallCtx = 0;
                opts.ctx_in = &smallCtx;
                opts.ctx_size_in = 1; // Too small

                result = process_monitor.PInvokes.bpf_prog_test_run_opts(programFd, &opts);
                Assert.AreNotEqual(0, result, "bpf_prog_test_run_opts should fail with undersized context");

                logger.LogDebug("SUCCESS: bpf_prog_test_run_opts correctly rejected undersized context");
            }
        }
        finally
        {
            // Clean up
            if (bpfObject != IntPtr.Zero)
            {
                process_monitor.PInvokes.bpf_object__close(bpfObject);
            }
        }
    }
}