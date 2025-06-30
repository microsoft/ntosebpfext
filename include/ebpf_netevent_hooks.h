// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stddef.h>
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by neteventebpfext.sys for use by eBPF programs.

// Versioning header structures for BPF program compatibility

// Define event types
#define NETEVENT_EVENT_TYPE_PKTMON_DROP 100
#define NETEVENT_EVENT_TYPE_PKTMON_FLOW 101

// Define capture header version
#define NETEVENT_PKTMON_EVENT_CURRENT_VERSION 1
// Define the length of the event header expected prior to the event data.
// Currently this length is equal to the size of PKTMON_EVT_STREAM_PACKET_HEADER which is defined in pktmonnpik.h.
#define PKTMON_EVENT_HEADER_LENGTH 0x35

// Capture header structure
typedef struct _netevent_data_header
{
    uint8_t type;
    uint16_t version;
} netevent_data_header_t;

// This structure is used to pass event data to the eBPF program.
// data_meta points to netevent_data_header_t (with versioning information) followed by pktmon structure
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
