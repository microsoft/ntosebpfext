// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace process_monitor
{
    internal static class PInvokes
    {
        const string ebpfApiDll = "EbpfApi.dll";

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr bpf_object__open([MarshalAs(UnmanagedType.LPStr)] string path);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void bpf_object__close(IntPtr obj);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int bpf_object__load(IntPtr bpf_object);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr bpf_object__find_map_by_name(IntPtr bpf_object, [MarshalAs(UnmanagedType.LPStr)] string name);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr bpf_object__find_program_by_name(IntPtr bpf_object, [MarshalAs(UnmanagedType.LPStr)] string name);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr bpf_program__attach(IntPtr bpf_program);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe IntPtr ebpf_ring_buffer__new(int map_fd, delegate* unmanaged[Cdecl]<IntPtr, IntPtr, nint, int> sample_cb, IntPtr ctx, ref process_monitor.Library.ProcessMonitorBPFLoader.ebpf_ring_buffer_opts opts);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ring_buffer__free(IntPtr ring_buffer);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int bpf_map__fd(IntPtr bpf_map);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int bpf_link__fd(IntPtr bpf_link);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int bpf_link_detach(IntPtr link_fd);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int bpf_link__destroy(IntPtr link_fd);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int bpf_map_lookup_elem(int fd, ref byte key, ref byte value);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int bpf_program__fd(IntPtr bpf_program);

        [DllImport(ebpfApiDll, CharSet = CharSet.Ansi, PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int bpf_prog_test_run_opts(int prog_fd, bpf_test_run_opts* opts);

        // Structure for bpf_prog_test_run_opts
        // This must match the native structure in libbpf
        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct bpf_test_run_opts
        {
            internal nuint sz;                  // size_t sz
            internal uint retval;               // __u32 retval
            internal int data_size_in;          // int data_size_in
            internal int data_size_out;         // int data_size_out
            internal void* data_in;             // const void *data_in
            internal void* data_out;            // void *data_out
            internal int ctx_size_in;           // int ctx_size_in
            internal int ctx_size_out;          // int ctx_size_out
            internal void* ctx_in;              // const void *ctx_in
            internal void* ctx_out;             // void *ctx_out
            internal int repeat;                // int repeat
            internal int duration;              // int duration
            internal int flags;                 // int flags
            internal uint cpu;                  // __u32 cpu
            internal uint batch_size;           // __u32 batch_size

            // Factory method to create a properly initialized instance
            // All fields except sz are initialized to their default values (0/null)
            internal static bpf_test_run_opts Create()
            {
                return new bpf_test_run_opts
                {
                    sz = (nuint)sizeof(bpf_test_run_opts)
                };
            }
        }

        // Structure for process_md_t
        // This must match the native definition in ebpf_ntos_hooks.h
        [StructLayout(LayoutKind.Sequential)]
        internal struct process_md_t
        {
            internal IntPtr command_start;      // uint8_t* command_start
            internal IntPtr command_end;        // uint8_t* command_end
            internal UInt64 process_id;         // uint64_t process_id
            internal UInt64 parent_process_id;  // uint64_t parent_process_id
            internal UInt64 creating_process_id;// uint64_t creating_process_id
            internal UInt64 creating_thread_id; // uint64_t creating_thread_id
            internal UInt64 creation_time;      // uint64_t creation_time
            internal UInt64 exit_time;          // uint64_t exit_time
            internal UInt32 process_exit_code;  // uint32_t process_exit_code
            internal byte operation;            // process_operation_t operation : 8
        }

        // Structure for process_notify_context_t
        // This must match the native definition in ntos_ebpf_ext_process.c
        // Note: EBPF_CONTEXT_HEADER is empty/marker, so we just include process_md_t and padding
        [StructLayout(LayoutKind.Sequential)]
        internal struct process_notify_context_t
        {
            // EBPF_CONTEXT_HEADER (empty marker)
            internal process_md_t process_md;
            internal IntPtr process;            // PEPROCESS
            internal IntPtr create_info;        // PPS_CREATE_NOTIFY_INFO
            internal IntPtr command_line_buffer;   // UNICODE_STRING.Buffer
            internal UInt16 command_line_length;   // UNICODE_STRING.Length
            internal UInt16 command_line_max_length; // UNICODE_STRING.MaximumLength
            internal IntPtr image_file_name_buffer;   // UNICODE_STRING.Buffer
            internal UInt16 image_file_name_length;   // UNICODE_STRING.Length
            internal UInt16 image_file_name_max_length; // UNICODE_STRING.MaximumLength
        }
    }
}
