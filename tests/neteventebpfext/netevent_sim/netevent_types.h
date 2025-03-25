// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

// #include <ntdef.h>
// typedef struct _EX_RUNDOWN_REF_CACHE_AWARE* PEX_RUNDOWN_REF_CACHE_AWARE;
// #include <pktmonnpik.h>

// #include "..\..\..\include\ebpf_netevent_hooks.h"
//
// Define some demo event types
//

// The event type we want to process
#define NOTIFY_EVENT_TYPE_NETEVENT_DROP 100
#define NOTIFY_EVENT_TYPE_NETEVENT_LOG 101

#pragma pack(push, 1) // Set packing to 1 byte boundary

// IP address structure
typedef struct _ip_address
{
    unsigned char octet1;
    unsigned char octet2;
    unsigned char octet3;
    unsigned char octet4;
} ip_address_t;

// Type definitions for drop events
typedef enum _drop_reason
{
    DROP_REASON_NONE = 0,
    DROP_REASON_INVALID_PACKET = 1,
    DROP_REASON_SECURITY_POLICY = 2,
    DROP_REASON_BANDWIDTH_LIMIT = 3,
    DROP_REASON_INACTIVE_TIMEOUT = 4,
} drop_reason;
typedef struct _netevent_payload
{

    ip_address_t source_ip;
    ip_address_t destination_ip;
    unsigned short source_port;
    unsigned short destination_port;

    // Event counter, for testing purposes
    unsigned long event_counter;
} netevent_payload_t;

//
// Packet descriptor used for event streaming
//
typedef struct _netevent_message_descriptor
{
    unsigned int packet_original_length;
    unsigned int packet_logged_length;
    unsigned int packet_metadata_length;
} netevent_message_descriptor_t;

//
// Metadata information used for event streaming
//
typedef struct _netevent_message_metadata
{
    unsigned long long pkt_group_id;
    unsigned short pkt_count;
    unsigned short appearance_count;
    unsigned short direction_name;
    unsigned short packet_type;
    unsigned short component_id;
    unsigned short edge_id;
    unsigned short filter_id;
    unsigned int drop_reason;
    unsigned int drop_location;
    unsigned short proc_num;
    unsigned long long timestamp;
} netevent_message_metadata_t;

//
// Packet header used for event streaming
//
typedef struct _netevent_message_header
{
    unsigned char event_id;
    netevent_message_descriptor_t packet_descriptor;
    netevent_message_metadata_t metadata;
} netevent_message_header_t;

//
// This structure is used to pass event data to the eBPF program.
//
typedef struct _netevent_message
{
    netevent_message_header_t header;
    netevent_payload_t payload;
} netevent_message_t;

#pragma pack(pop)
