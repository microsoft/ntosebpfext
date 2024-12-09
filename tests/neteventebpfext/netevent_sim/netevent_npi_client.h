// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include "ebpf_windows.h"

// Specific Event type to the neteventebpfext extension.
typedef struct
{
    // Note: the BPF verifier limits the ability to just pass the pointer to the start of the buffer and its length.
    unsigned char* event_data_start; ///< Pointer to start of the data associated with the event.
    unsigned char* event_data_end; ///< Pointer to end of the data associated with the event (i.e. first byte *outside*
                                   ///< the memory range).
} netevent_event_info_t;
typedef void (*netevent_push_event)(netevent_event_info_t*);

typedef struct netevent_ext_header
{
    uint16_t version; ///< Version of the extension data structure.
    size_t size;      ///< Size of the netevent function addresses structure.
} netevent_ext_header_t;

// This is the type definition for the netevent helper function addresses.
typedef struct netevent_ext_function_addresses
{
    netevent_ext_header_t header;
    uint32_t helper_function_count;
    uint64_t* helper_function_address;
} netevent_ext_function_addresses_t;