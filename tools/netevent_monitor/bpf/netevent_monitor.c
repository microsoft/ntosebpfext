// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This BPF program listens for events from the netevent driver, and stores them into a ring buffer map.

#include "bpf_helpers.h"
#include "ebpf_netevent_hooks.h"

#include <stddef.h>
#include <stdint.h>

// Ring-buffer for netevent_event_md_t.
#define EVENTS_MAP_SIZE (512 * 1024)
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
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
    uint8_t event_type = 0;

    if (ctx != NULL && ctx->event_data_start != NULL && (ctx->event_data_end - ctx->event_data_start) > 1) {

        event_type = *(
            ctx->event_data_start); // The event type is on the first byte of the buffer (like for Cilium event buffers)

        if (event_type == NOTIFY_EVENT_TYPE_NETEVENT) {
            // Push the event to the netevent_events_map.
            bpf_ringbuf_output(
                &netevent_events_map, ctx->event_data_start, (ctx->event_data_end - ctx->event_data_start), 0);
        }
        return 0;
    }

    return 1;
}
