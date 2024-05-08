// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

namespace process_monitor.Library;

public readonly struct ProcessDestroyedEventArgs
{
    public ProcessDestroyedEventArgs(uint processId, string imageFileName, string commandLine, DateTime createTime, DateTime exitTime, uint exitCode)
    {
        ProcessId = processId;
        ImageFileName = imageFileName;
        CommandLine = commandLine;
        CreateTime = createTime;
        ExitTime = exitTime;
        ExitCode = exitCode;
    }

    public readonly uint ProcessId;
    public readonly string ImageFileName;
    public readonly string CommandLine;
    public readonly DateTime CreateTime;
    public readonly DateTime ExitTime;
    public readonly uint ExitCode;
}
