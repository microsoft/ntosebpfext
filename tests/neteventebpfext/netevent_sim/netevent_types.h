// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

// Define some demo event types
#define NOTIFY_EVENT_TYPE_NETEVENT 100 // The event type we want to process

typedef enum _drop_reason
{
    DROP_REASON_NONE = 0,
    DROP_REASON_INVALID_PACKET = 1,
    DROP_REASON_SECURITY_POLICY = 2,
    DROP_REASON_BANDWIDTH_LIMIT = 3,
    DROP_REASON_INACTIVE_TIMEOUT = 4,
} drop_reason;

#pragma pack(push, 1) // Set packing to 1 byte boundary
typedef struct _ip_address
{
    unsigned char octet1;
    unsigned char octet2;
    unsigned char octet3;
    unsigned char octet4;
} ip_address_t;

typedef struct _netevent_type_drop
{
    ip_address_t source_ip;
    ip_address_t destination_ip;
    unsigned short source_port;
    unsigned short destination_port;
    unsigned short reason;

    // Event counter, for testing purposes
    unsigned long event_counter;
} netevent_type_drop_t;

#pragma pack(pop) // Restore default packing