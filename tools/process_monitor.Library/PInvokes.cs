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
        internal static extern unsafe IntPtr ring_buffer__new(int map_fd, delegate* unmanaged[Cdecl]<IntPtr, IntPtr, nint, int> sample_cb, IntPtr ctx, IntPtr opts);

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
    }
}
