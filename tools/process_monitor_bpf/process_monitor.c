// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This BPF program listens for process events and logs the process id, parent process id, creating process id, creating
// thread id, and operation to a ring buffer. It also logs the image path and command line of the process to LRU hash
// maps.

#include "bpf_helpers.h"
#include "ebpf_ntos_hooks.h"

// The non variable fields from the process_md_t struct.
// Note: this must be kept in sync with the C# version in process_monitor.Library's ProcessMonitorBPFLoader.cs
typedef struct
{
    uint32_t process_id;
    uint32_t parent_process_id;
    uint32_t creating_process_id;
    uint32_t creating_thread_id;
    uint64_t creation_time; ///< Process creation time.
    uint64_t exit_time;     ///< Process exit time.
    uint32_t process_exit_code;
    uint8_t operation;
} process_info_t;

#define MAX_PATH (496 - sizeof(process_info_t))

// LRU hash for storing the image path of a process.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, uint32_t); // key is the process id.
    __type(value, char[MAX_PATH]);
    __uint(max_entries, 1024);
} process_map SEC(".maps");

// LRU hash for storing the command line of a process.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, uint32_t); // key is the process id.
    __type(value, char[MAX_PATH]);
    __uint(max_entries, 1024);
} command_map SEC(".maps");

// Ring-buffer for process_info_t.
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 64);
} process_ringbuf SEC(".maps");

// The following line is optional, but is used to verify
// that the ProcesMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
process_hook_t ProcesMonitor;

SEC("process")
int
ProcessMonitor(process_md_t* ctx)
{
    process_info_t process_info;

    memset(&process_info, 0, sizeof(process_info));

    process_info.process_id = ctx->process_id;
    process_info.parent_process_id = ctx->parent_process_id;
    process_info.creating_process_id = ctx->creating_process_id;
    process_info.creating_thread_id = ctx->creating_thread_id;
    process_info.creation_time = ctx->creation_time;
    process_info.exit_time = ctx->exit_time;
    process_info.process_exit_code = ctx->process_exit_code;
    process_info.operation = ctx->operation;

    if (process_info.operation == PROCESS_OPERATION_CREATE) {
        uint8_t buffer[MAX_PATH];

        memset(buffer, 0, sizeof(buffer));

        memcpy_s(buffer, sizeof(buffer), ctx->command_start, ctx->command_end - ctx->command_start);
        bpf_map_update_elem(&command_map, &process_info.process_id, buffer, BPF_ANY);

        // Reset the buffer.
        memset(buffer, 0, sizeof(buffer));

        // Copy image path into the LRU hash.
        bpf_process_get_image_path(ctx, buffer, sizeof(buffer));
        bpf_map_update_elem(&process_map, &process_info.process_id, buffer, BPF_ANY);
    }
    bpf_ringbuf_output(&process_ringbuf, &process_info, sizeof(process_info), 0);
    return 0;
}
