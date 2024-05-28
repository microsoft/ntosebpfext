// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

namespace process_monitor;

// Inspired by https://learn.microsoft.com/en-us/dotnet/core/extensions/console-log-formatter#implement-custom-color-formatting
internal static class TextWriterExtensions
{
    const string DefaultForegroundColor = "\x1B[39m\x1B[22m";
    const string DefaultBackgroundColor = "\x1B[49m";

    public static void WriteWithColor(
        this TextWriter textWriter,
        string message,
        ConsoleColor? background = null,
        ConsoleColor? foreground = null) => WriteWithColorCore(textWriter, message, withNewline: false, background, foreground);

    public static void WriteLineWithColor(
        this TextWriter textWriter,
        string message,
        ConsoleColor? background = null,
        ConsoleColor? foreground = null) => WriteWithColorCore(textWriter, message, withNewline: true, background, foreground);

    private static void WriteWithColorCore(
        this TextWriter textWriter,
        string message,
        bool withNewline,
        ConsoleColor? background = null,
        ConsoleColor? foreground = null)
    {
        // Order:
        //   1. background color
        //   2. foreground color
        //   3. message
        //   4. reset foreground color
        //   5. reset background color

        var backgroundColor = background.HasValue ? GetBackgroundColorEscapeCode(background.Value) : null;
        var foregroundColor = foreground.HasValue ? GetForegroundColorEscapeCode(foreground.Value) : null;

        if (backgroundColor is not null)
        {
            textWriter.Write(backgroundColor);
        }
        if (foregroundColor is not null)
        {
            textWriter.Write(foregroundColor);
        }

        try
        {
            if (withNewline)
            {
                textWriter.WriteLine(message);
            }
            else
            {
                textWriter.Write(message);
            }
        }
        finally
        {
            if (foregroundColor is not null)
            {
                textWriter.Write(DefaultForegroundColor);
            }
            if (backgroundColor is not null)
            {
                textWriter.Write(DefaultBackgroundColor);
            }
        }
    }

    static string GetForegroundColorEscapeCode(ConsoleColor color) =>
        color switch
        {
            ConsoleColor.Black => "\x1B[30m",
            ConsoleColor.DarkRed => "\x1B[31m",
            ConsoleColor.DarkGreen => "\x1B[32m",
            ConsoleColor.DarkYellow => "\x1B[33m",
            ConsoleColor.DarkBlue => "\x1B[34m",
            ConsoleColor.DarkMagenta => "\x1B[35m",
            ConsoleColor.DarkCyan => "\x1B[36m",
            ConsoleColor.Gray => "\x1B[37m",
            ConsoleColor.Red => "\x1B[1m\x1B[31m",
            ConsoleColor.Green => "\x1B[1m\x1B[32m",
            ConsoleColor.Yellow => "\x1B[1m\x1B[33m",
            ConsoleColor.Blue => "\x1B[1m\x1B[34m",
            ConsoleColor.Magenta => "\x1B[1m\x1B[35m",
            ConsoleColor.Cyan => "\x1B[1m\x1B[36m",
            ConsoleColor.White => "\x1B[1m\x1B[37m",

            _ => DefaultForegroundColor
        };

    static string GetBackgroundColorEscapeCode(ConsoleColor color) =>
        color switch
        {
            ConsoleColor.Black => "\x1B[40m",
            ConsoleColor.DarkRed => "\x1B[41m",
            ConsoleColor.DarkGreen => "\x1B[42m",
            ConsoleColor.DarkYellow => "\x1B[43m",
            ConsoleColor.DarkBlue => "\x1B[44m",
            ConsoleColor.DarkMagenta => "\x1B[45m",
            ConsoleColor.DarkCyan => "\x1B[46m",
            ConsoleColor.Gray => "\x1B[47m",

            _ => DefaultBackgroundColor
        };
}