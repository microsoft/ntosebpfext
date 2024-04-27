// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This BPF program listens for events from the pktmon driver, and stores them into a ring buffer map.

#include "bpf_helpers.h"
#include "ebpf_pktmon_hooks.h"

#include <stddef.h>

// Ring-buffer for pktmon_event_md_t.
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 500000 * 200); // 500000 events of ~200 bytes each.
} pktmon_events_map SEC(".maps");

// The following line is optional, but is used to verify
// that the PktmonMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
pktmon_event_hook_t PktmonMonitor;

SEC("pktmon_monitor")
int
PktmonMonitor(pktmon_event_md_t* ctx)
{
    if (*(ctx->event_data_start) == NOTIFY_EVENT_TYPE_PKTMON) {
        // Push the event to the pktmon_events_map.
        bpf_ringbuf_output(
            &pktmon_events_map, ctx->event_data_start, ctx->event_data_end - ctx->event_data_start + 1, 0);
    }

    return 0;
}
