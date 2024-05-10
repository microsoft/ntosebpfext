// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

using Microsoft.Extensions.Logging;
using process_monitor;
using process_monitor.Library;
using System.Text;

var exitCode = 0;
ManualResetEvent shutdownEvent = new(false);

Console.OutputEncoding = Encoding.UTF8;

Console.Error.WriteLine("Press Ctrl-C to shutdown");
Console.CancelKeyPress += (sender, e) =>
{
    if (e.SpecialKey == ConsoleSpecialKey.ControlC)
    {
        e.Cancel = true; // We'll do our own shutdown
        shutdownEvent.Set();
    }
};

{
    using var loggerFactory = LoggerFactory.Create(builder =>
    {
        _ = builder
        .AddProcessMonitorFormatter();
    });

    var programLogger = loggerFactory.CreateLogger<Program>();

    try
    {
        using var processMonitor = new ProcessMonitor(loggerFactory.CreateLogger<ProcessMonitor>());

        processMonitor.ProcessCreated += (sender, e) =>
        {
            programLogger.LogInformation("Process created: PID:{pid}, Image:{imageFileName}, CommandLine:{commandLine}, ParentPID:{parentPid}, Create Time:{createTime}",
                e.ProcessId, e.ImageFileName, e.CommandLine, e.ParentProcessId, e.CreateTime);
        };

        processMonitor.ProcessDestroyed += (sender, e) =>
        {
            programLogger.LogInformation("Process destroyed: PID:{pid}, Image:{imageFileName}, CommandLine:{commandLine}, Exit Time:{exitTime}, Exit Code:{exitCode}",
                e.ProcessId, e.ImageFileName, e.CommandLine, e.ExitTime, e.ExitCode);
        };

        // Wait for Ctrl-C.
        shutdownEvent.WaitOne();
    }
    catch (Exception ex)
    {
        programLogger.LogError(ex, "");
        exitCode = 1;
    }
} // At this point the logger factory is disposed, we have flushed all logs

Environment.ExitCode = exitCode;