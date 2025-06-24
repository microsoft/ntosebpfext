// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stddef.h>
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by neteventebpfext.sys for use by eBPF programs.

// Versioning header structures for BPF program compatibility
#define NOTIFY_COMMON_HEADER \
    uint8_t type;         \
    uint8_t subtype;      \
    uint16_t source;      \
    uint32_t hash;

#define NOTIFY_CAPTURE_HEADER                           \
    NOTIFY_COMMON_HEADER                                \
    uint32_t length_original; /* Length of original packet */ \
    uint16_t length_captured;  /* Length of captured bytes */  \
    uint16_t version;  /* Capture header version */

// Define capture header version
#define NETEVENT_CAPTURE_HEADER_CURRENT_VERSION 1

// Capture header structure
typedef struct _netevent_capture_header {
    NOTIFY_CAPTURE_HEADER
} netevent_capture_header_t;

// Example usage in BPF programs:
// netevent_capture_header_t* header = (netevent_capture_header_t*)ctx->data_meta;
// if (header && header->version == NETEVENT_CAPTURE_HEADER_CURRENT_VERSION) {
//     // Access versioning information
//     uint8_t event_type = header->type;
//     uint32_t original_length = header->length_original;
// }
// // Access event data (backward compatible)
// uint8_t* event_data = ctx->data;
// uint8_t* event_end = ctx->data_end;

// Forward declaration for PKTMON event stream packet header
// Only the EventId field is needed for event type extraction
typedef struct _pktmon_evt_stream_packet_header {
    uint32_t EventId;
    // Additional fields would be defined by the platform header
} PKTMON_EVT_STREAM_PACKET_HEADER;

// This structure is used to pass event data to the eBPF program.
// After versioning changes:
// - data_meta points to netevent_capture_header_t with versioning information
// - data points to the actual event payload (maintains backward compatibility)
// - data_end points to the end of the entire buffer (header + payload)
typedef struct _netevent_event_md
{
    uint8_t* data_meta;
    uint8_t* data;
    uint8_t* data_end;
} netevent_event_md_t;

// Packet capture type.
typedef enum _netevent_capture_type
{
    NeteventCapture_All = 1,
    NeteventCapture_Flow,
    NeteventCapture_Drop,
    NeteventCapture_None
} netevent_capture_type_t;

typedef struct _netevent_attach_opts
{
    netevent_capture_type_t capture_type;
} netevent_attach_opts_t;

/*
 * @brief Write an event into the ring buffer.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_NETEVENT
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_NETEVENT
 *
 * @param[in] context \ref netevent_event_md_t
 * @return STATUS_SUCCESS insertion succeeded.
 * Value of STATUS_SUCCESS is 0x0.
 */
typedef int
netevent_event_hook_t(netevent_event_md_t* context);

// NetEvent helper functions.
#define NETEVENT_EXT_HELPER_FN_BASE 0xFFFF

#if !defined(__doxygen) && !defined(EBPF_HELPER)
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

typedef enum
{
    BPF_FUNC_netevent_push_event = NETEVENT_EXT_HELPER_FN_BASE + 1,
} ebpf_netevent_event_helper_id_t;

/**
 * @brief Push an event to the netevent event ring buffer.
 *
 * @param[in] context Event metadata.
 *
 * @retval =0 Succeeded inserting the event.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_netevent_push_event, (netevent_event_md_t * ctx));
#ifndef __doxygen
#define bpf_netevent_push_event ((bpf_netevent_push_event_t)BPF_FUNC_netevent_push_event)
#endif
