// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

namespace process_monitor.Library;

public readonly record struct ProcessDestroyedEventArgs(
    uint ProcessId,
    string ImageFileName,
    string CommandLine,
    DateTime CreateTime,
    DateTime ExitTime,
    uint ExitCode);
