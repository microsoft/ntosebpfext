// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

namespace process_monitor.Library;

public readonly record struct ProcessCreatedEventArgs(
    uint ProcessId,
    string ImageFileName,
    string CommandLine,
    uint ParentProcessId,
    uint CreatingProcessId,
    uint CreatingThreadId,
    DateTime CreateTime);
