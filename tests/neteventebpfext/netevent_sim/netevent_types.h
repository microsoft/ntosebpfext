// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

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

// Common header for all events
typedef struct _event_header
{
    unsigned char event_type; ///< Event type. This is the first byte of the event data, for compatibility with
                              ///< potential usage with Cilium eBPF programs.
} event_header_t;

// Type definitions for drop events
typedef enum _drop_reason
{
    DROP_REASON_NONE = 0,
    DROP_REASON_INVALID_PACKET = 1,
    DROP_REASON_SECURITY_POLICY = 2,
    DROP_REASON_BANDWIDTH_LIMIT = 3,
    DROP_REASON_INACTIVE_TIMEOUT = 4,
} drop_reason;
typedef struct _netevent_message
{
    event_header_t header;

    ip_address_t source_ip;
    ip_address_t destination_ip;
    unsigned short source_port;
    unsigned short destination_port;
    unsigned short reason;

    // Event counter, for testing purposes
    unsigned long event_counter;
} netevent_message_t;

#pragma pack(pop) // Restore default packing