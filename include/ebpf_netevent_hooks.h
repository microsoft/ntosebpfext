// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stddef.h>
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by neteventebpfext.sys for use by eBPF programs.

#pragma pack(push, 1)

// Packet descriptor used for event streaming.
typedef struct _netevent_packet_descriptor
{
    uint32_t packet_original_length; // Original length of the packet.
    uint32_t packet_logged_length;   // The original packet might have been truncated during logging. This field
                                     // represents the size of the received packet pointed to by `data_start`.
    uint32_t packet_metadata_length; // Length of the packet metadata. Can be greater that sizeof(packet_metadata_t) if
                                     // metadata fields are added in the future.
} netevent_packet_descriptor_t;

// Metadata information used for event streaming.
typedef struct _netevent_metadata
{
    uint64_t pkt_group_id;
    uint16_t pkt_count;
    uint16_t appearance_count;
    uint16_t direction_name;
    uint16_t packet_type;
    uint16_t component_id;
    uint16_t edge_id;
    uint16_t filter_id;
    uint32_t drop_reason;
    uint32_t drop_location;
    uint16_t proc_num;
    uint64_t timestamp;
} netevent_metadata_t;

// Packet header used for event streaming.
typedef struct _netevent_packet_header
{
    uint8_t event_id;
    netevent_packet_descriptor_t packet_descriptor;
    netevent_metadata_t metadata;
} netevent_packet_header_t;

#pragma pack(pop)

// This structure is used to pass event data to the eBPF program.
typedef struct _netevent_event_md
{
    uint8_t* data_meta;
    uint8_t* data_start;
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
