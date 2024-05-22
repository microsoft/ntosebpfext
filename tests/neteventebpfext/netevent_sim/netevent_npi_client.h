// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

typedef struct
{
    // Note: the BPF verifier limits the ability to just pass the pointer to the start of the buffer and its length.
    unsigned char* event_data_start; ///< Pointer to start of the data associated with the event.
    unsigned char* event_data_end; ///< Pointer to end of the data associated with the event (i.e. first byte *outside*
                                   ///< the memory range).
} netevent_event_info_t;

typedef void (*netevent_push_event)(netevent_event_info_t*);

typedef struct
{

    const void* netevent_ext_helper_functions_t[];
} netevent_dispatch_address_table_t;

// Define the NPI client dispatch table
typedef struct _NETEVENT_NPI_CLIENT_DISPATCH
{
    void* netevent_dispatch;
} NETEVENT_NPI_CLIENT_DISPATCH, *PNETEVENT_NPI_CLIENT_DISPATCH;
