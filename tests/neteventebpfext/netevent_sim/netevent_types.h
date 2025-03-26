// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

typedef struct _EX_RUNDOWN_REF_CACHE_AWARE* PEX_RUNDOWN_REF_CACHE_AWARE;
#include <pktmonnpik.h>

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
    unsigned char event_id;
    ip_address_t source_ip;
    ip_address_t destination_ip;
    unsigned short source_port;
    unsigned short destination_port;

    // Event counter, for testing purposes
    unsigned long event_counter;
} netevent_payload_t;

// This structure is used to pass event data to the eBPF program.
typedef struct _netevent_message
{
    PKTMON_EVT_STREAM_PACKET_HEADER header;
    netevent_payload_t payload;
} netevent_message_t;

#pragma pack(pop)
