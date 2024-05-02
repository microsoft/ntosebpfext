// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This BPF program listens for events from the pktmon driver, and stores them into a ring buffer map.

#include "bpf_helpers.h"
#include "ebpf_pktmon_hooks.h"

#include <stddef.h>
#include <stdint.h>

// Ring-buffer for pktmon_event_md_t.
#define EVENTS_MAP_SIZE (512 * 1024)
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EVENTS_MAP_SIZE);
} pktmon_events_map SEC(".maps");

// The following line is optional, but is used to verify
// that the PktmonMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
pktmon_event_hook_t PktmonMonitor;

SEC("pktmon_monitor")
int
PktmonMonitor(pktmon_event_md_t* ctx)
{
    uint8_t event_type = 0;

    if (ctx != NULL && ctx->event_data_start != NULL) {

        event_type = *(
            ctx->event_data_start); // The event type is on the firts byte of the buffer (like for Cilium event buffers)

        if (event_type == NOTIFY_EVENT_TYPE_PKTMON) {
            // Push the event to the pktmon_events_map.
            bpf_ringbuf_output(
                &pktmon_events_map, ctx->event_data_start, (ctx->event_data_end - ctx->event_data_start + 1), 0);
        }

        return 0;
    }

    return 1;
}
