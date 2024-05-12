// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;

namespace process_monitor;

public static class ConsoleLoggerExtensions
{
    public static ILoggingBuilder AddProcessMonitorFormatter(
        this ILoggingBuilder builder) =>
        builder.AddConsole(options => options.FormatterName = "processMonitorLoggingFormatter")
            .AddConsoleFormatter<CustomFormatter, ConsoleFormatterOptions>(static (_) => { });
}

public sealed class CustomFormatter : ConsoleFormatter
{
    public CustomFormatter()
        // Case insensitive
        : base("processMonitorLoggingFormatter")
    { }

    internal static ConsoleColor? ColorFromLogLevel(LogLevel logLevel) =>
        logLevel switch
        {
            LogLevel.Trace => null,
            LogLevel.Debug => null,
            LogLevel.Information => null,
            LogLevel.None => null,
            LogLevel.Warning => ConsoleColor.Yellow,
            LogLevel.Error => ConsoleColor.Red,
            LogLevel.Critical => ConsoleColor.Red,
            _ => null,
        };

    public override void Write<TState>(
        in LogEntry<TState> logEntry,
        IExternalScopeProvider? scopeProvider,
        TextWriter textWriter)
    {
        string? message =
            logEntry.Formatter?.Invoke(
                logEntry.State, logEntry.Exception);

        if (message is null)
        {
            return;
        }

        var foregroundForLogLevel = ColorFromLogLevel(logEntry.LogLevel);

        switch(logEntry.LogLevel)
        {
            case LogLevel.Trace:
            case LogLevel.Debug:
            case LogLevel.Information:
            case LogLevel.None:
                break;
            case LogLevel.Warning:
                textWriter.WriteWithColor("[WARN] ", foreground: foregroundForLogLevel);
                break;
            case LogLevel.Error:
                textWriter.WriteWithColor("[ERROR] ", foreground: foregroundForLogLevel);
                break;
            case LogLevel.Critical:
                textWriter.WriteWithColor("[CRITICAL] ", foreground: foregroundForLogLevel);
                break;
        }

        if (logEntry.Exception is not null)
        {
            textWriter.WriteLineWithColor(logEntry.Exception.GetFormattedTextForLogging(message, lineSeparator: Environment.NewLine), foreground: foregroundForLogLevel);
        }
        else
        {
            textWriter.WriteLineWithColor(message, foreground: foregroundForLogLevel);
        }
    }
}
