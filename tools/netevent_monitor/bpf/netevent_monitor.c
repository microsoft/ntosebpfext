// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This BPF program listens for events from the netevent driver, and stores them into a ring buffer map.

#include "bpf_helpers.h"
#include "ebpf_netevent_hooks.h"

#include <stddef.h>
#include <stdint.h>

#define EVENT_SIZE_MAX 128

// Ring-buffer for netevent_event_md_t.
#define EVENTS_MAP_SIZE (512 * 1024)
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, EVENTS_MAP_SIZE);
} netevent_events_map SEC(".maps");

// The following line is optional, but is used to verify
// that the NetEventMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
netevent_event_hook_t NetEventMonitor;

SEC("netevent_monitor")
int
NetEventMonitor(netevent_event_md_t* ctx)
{
    int result = -1;

    uint32_t ctx_len = ctx->data_end - ctx->data_meta;
    uint32_t data_len = ctx->data_end - ctx->data;
    uint32_t header_len = sizeof(netevent_data_header_t) + PKTMON_EVENT_HEADER_LENGTH;
    uint32_t event_len = header_len;

    if (ctx->data_meta + header_len == ctx->data) {
        if (data_len > EVENT_SIZE_MAX) {
            data_len = EVENT_SIZE_MAX;
        }
        event_len += data_len;
        return bpf_perf_event_output(ctx, &netevent_events_map, EBPF_MAP_FLAG_CURRENT_CPU, ctx->data_meta, event_len);
    }

    return -1;
}
