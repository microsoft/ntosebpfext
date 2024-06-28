// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;

namespace process_monitor.Library
{
    internal static class ProcessMonitorBPFLoader
    {
        private static IntPtr process_monitor_bpfObject = IntPtr.Zero;
        private static IntPtr process_monitor_link = IntPtr.Zero;
        private static IntPtr process_ringbuf = IntPtr.Zero;
        private static IntPtr process_map = IntPtr.Zero;
        private static int process_map_fd = 0;
        private static IntPtr command_map = IntPtr.Zero;
        private static int command_map_fd = 0;
        private static bool _isShutdown;
        private static readonly object _lock = new();
        private static readonly List<ProcessMonitor> _processMonitors = [];
        private static readonly IntPtr process_info_t_process_id_offset = Marshal.OffsetOf<process_info_t>(nameof(process_info_t.process_id));

        // Note: this must be kept in sync with the C version in process_monitor.sys (process_monitor.c)
        [StructLayout(LayoutKind.Sequential)]
#pragma warning disable IDE1006 // Naming Styles - this matches the native definition's name
        internal readonly struct process_info_t
#pragma warning restore IDE1006 // Naming Styles
        {
            internal readonly UInt32 process_id;
            internal readonly UInt32 parent_process_id;
            internal readonly UInt32 creating_process_id;
            internal readonly UInt32 creating_thread_id;
            internal readonly UInt64 creation_time;
            internal readonly UInt64 exit_time;
            internal readonly UInt32 process_exit_code;
            internal readonly byte operation;
        }

        internal static void Subscribe(ProcessMonitor pm, ILogger logger)
        {
            lock (_lock)
            {
                if (_processMonitors.Count == 0)
                {
                    Initialize(logger);
                }

                _processMonitors.Add(pm);
            }
        }

        internal static void Unsubscribe(ProcessMonitor pm)
        {
            lock (_lock)
            {
                _processMonitors.Remove(pm);

                if (_processMonitors.Count == 0)
                {
                    Shutdown();
                }
            }
        }

        private static void Initialize(ILogger logger)
        {
            unsafe
            {
                process_monitor_bpfObject = PInvokes.bpf_object__open("process_monitor.sys");
                if (process_monitor_bpfObject == IntPtr.Zero)
                {
                    throw new InvalidOperationException("bpf_object__open for process_monitor.sys failed!");
                }
                else
                {
                    logger.LogDebug("SUCCESS: bpf_object__open(process_monitor.sys) worked");
                }

                var loadResult = PInvokes.bpf_object__load(process_monitor_bpfObject);

                if (loadResult < 0)
                {
                    throw new InvalidOperationException($"bpf_object__load for process_monitor.sys failed with error code: {loadResult}.  Check that the ntosebpfext service is running.");
                }
                else
                {
                    logger.LogDebug("SUCCESS: bpf_object__load succeeded!  result: {loadResult}", loadResult);
                }
                (process_map, process_map_fd) = LoadMapByName("process_map", logger);
                (command_map, command_map_fd) = LoadMapByName("command_map", logger);

                var process_monitor = PInvokes.bpf_object__find_program_by_name(process_monitor_bpfObject, "ProcessMonitor");
                if (process_monitor == IntPtr.Zero)
                {
                    throw new InvalidOperationException("bpf_object__find_program_by_name(ProcessMonitor) failed!");
                }
                else
                {
                    logger.LogDebug("SUCCESS: bpf_object__find_program_by_name succeeded!");
                }

                process_monitor_link = PInvokes.bpf_program__attach(process_monitor);
                if (process_monitor_link == IntPtr.Zero)
                {
                    throw new InvalidOperationException("bpf_program_attach(ProcessMonitor) failed!");
                }
                else
                {
                    logger.LogDebug("SUCCESS: bpf_program_attach(ProcessMonitor) succeeded!");
                }

                // Attach to ring buffer
                (_, var process_ringbuf_map_fd) = LoadMapByName("process_ringbuf", logger);
                process_ringbuf = PInvokes.ring_buffer__new(process_ringbuf_map_fd, &ProcessMonitor_history_callback, IntPtr.Zero, IntPtr.Zero);
                if (process_ringbuf == IntPtr.Zero)
                {
                    throw new InvalidOperationException("ring_buffer__new(process_ringbuf) failed!");
                }
                else
                {
                    logger.LogDebug("SUCCESS: ring_buffer__new(process_ringbuf) succeeded!");
                }
            }
        }

        private static unsafe (IntPtr map, int mapFD) LoadMapByName(string mapName, ILogger logger)
        {
            var map = PInvokes.bpf_object__find_map_by_name(process_monitor_bpfObject, mapName);

            if (map == IntPtr.Zero)
            {
                var ex = new InvalidOperationException($"bpf_object__find_map_by_name(\"{mapName}\") failed!");
                logger.LogError(ex, "");
                throw ex;
            }
            else
            {
                logger.LogDebug("SUCCESS: bpf_object__find_map_by_name(\"{mapName}\") succeeded!", mapName);
            }

            var mapFD = PInvokes.bpf_map__fd(map);

            return (map, mapFD);
        }

        private static unsafe string GetUnicodeStringFromBpfMapFD(int mapFD, process_info_t* evt)
        {
            Span<byte> utf16BytesOnStack = stackalloc byte[1024];

            var addrOfPID = (byte*)evt + process_info_t_process_id_offset;
            var byteSpanOfPID = new Span<byte>(addrOfPID, sizeof(uint));

            PInvokes.bpf_map_lookup_elem(mapFD,
                                         key: ref MemoryMarshal.AsRef<byte>(byteSpanOfPID),
                                         value: ref MemoryMarshal.AsRef<byte>(utf16BytesOnStack));

            return Encoding.Unicode.GetString(utf16BytesOnStack).Trim('\0');
        }

        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        internal unsafe static int ProcessMonitor_history_callback(IntPtr ctx, IntPtr data, IntPtr size)
        {
            if (size != Marshal.SizeOf<process_info_t>())
            {
                return 0;
            }

            process_info_t* evt = (process_info_t*)data;

            var file_name_str = GetUnicodeStringFromBpfMapFD(process_map_fd, evt);
            var command_line_str = GetUnicodeStringFromBpfMapFD(command_map_fd, evt);

            if (evt->operation == 0 /* 0 == PROCESS_OPERATION_COMPLETE */)
            {
                var createdArgs = new ProcessCreatedEventArgs()
                {
                    ProcessId = evt->process_id,
                    ImageFileName = file_name_str,
                    CommandLine = command_line_str,
                    ParentProcessId = evt->parent_process_id,
                    CreatingProcessId = evt->creating_process_id,
                    CreatingThreadId = evt->creating_thread_id,
                    CreateTime = DateTime.FromFileTime((long)evt->creation_time)
                };

                lock (_lock)
                {
                    foreach (var pm in _processMonitors)
                    {
                        pm.RaiseProcessCreated(createdArgs);
                    }
                }
            }
            else if (evt->operation == 1 /* 1 == PROCESS_OPERATION_DESTROY */)
            {
                var destroyedArgs = new ProcessDestroyedEventArgs()
                {
                    ProcessId = evt->process_id,
                    ImageFileName = file_name_str,
                    CommandLine = command_line_str,
                    CreateTime = DateTime.FromFileTime((long)evt->creation_time),
                    ExitTime = DateTime.FromFileTime((long)evt->exit_time),
                    ExitCode = evt->process_exit_code
                };

                lock (_lock)
                {
                    foreach (var pm in _processMonitors)
                    {
                        pm.RaiseProcessDestroyed(destroyedArgs);
                    }
                }
            }

            return 0;
        }

        internal static void Shutdown()
        {
            if (!_isShutdown)
            {
                // Free unmanaged resources
                // If we never got to the point of a successful bpf_object__open, then there's nothing to clean up.
                if (process_monitor_bpfObject != IntPtr.Zero)
                {
                    if (process_monitor_link != IntPtr.Zero)
                    {
                        // Detach from the attach point.
                        var link_fd = PInvokes.bpf_link__fd(process_monitor_link);
                        PInvokes.bpf_link_detach(link_fd);
                        PInvokes.bpf_link__destroy(process_monitor_link);
                        process_monitor_link = IntPtr.Zero;
                    }

                    if (process_ringbuf != IntPtr.Zero)
                    {
                        // Close ring buffer.
                        PInvokes.ring_buffer__free(process_ringbuf);
                        process_ringbuf = IntPtr.Zero;
                    }

                    // Free the BPF object.
                    PInvokes.bpf_object__close(process_monitor_bpfObject);
                    process_monitor_bpfObject = IntPtr.Zero;
                }

                _isShutdown = true;
            }
        }
    }
}
