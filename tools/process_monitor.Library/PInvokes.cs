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
        }
    }
}
