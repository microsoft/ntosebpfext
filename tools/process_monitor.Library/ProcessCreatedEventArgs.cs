// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

namespace process_monitor.Library;

public readonly struct ProcessCreatedEventArgs
{
    public ProcessCreatedEventArgs(uint processId, string imageFileName, string commandLine, uint parentProcessId, uint creatingProcessId, uint creatingThreadId, DateTime createTime)
    {
        ProcessId = processId;
        ImageFileName = imageFileName;
        CommandLine = commandLine;
        ParentProcessId = parentProcessId;
        CreatingProcessId = creatingProcessId;
        CreatingThreadId = creatingThreadId;
        CreateTime = createTime;
    }

    public readonly uint ProcessId;
    public readonly string ImageFileName;
    public readonly string CommandLine;
    public readonly uint ParentProcessId;
    public readonly uint CreatingProcessId;
    public readonly uint CreatingThreadId;
    public readonly DateTime CreateTime;
}
