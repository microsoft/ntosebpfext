// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

// Specific Event type to the neteventebpfext extension.
typedef struct
{
    // Note: the BPF verifier limits the ability to just pass the pointer to the start of the buffer and its length.
    unsigned char* event_data_start; ///< Pointer to start of the data associated with the event.
    unsigned char* event_data_end; ///< Pointer to end of the data associated with the event (i.e. first byte *outside*
                                   ///< the memory range).
} netevent_event_info_t;
typedef void (*netevent_push_event)(netevent_event_info_t*);

// Header of an eBPF extension data structure.
// Every eBPF extension data structure must start with this header.
// New fields can be added to the end of an eBPF extension data structure
// without breaking backward compatibility. The version field must be
// updated only if the new data structure is not backward compatible.
typedef struct _ebpf_extension_header
{
    UINT16 version; ///< Version of the extension data structure.
    size_t size;    ///< Size of the extension data structure.
} ebpf_extension_header_t;

// This is the type definition for the eBPF helper function addresses
// when version is EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION.
typedef struct _ebpf_helper_function_addresses
{
    ebpf_extension_header_t header;
    UINT32 helper_function_count;
    UINT64* helper_function_address;
} ebpf_helper_function_addresses_t;

// Define the NPI client dispatch table
typedef struct _NETEVENT_NPI_CLIENT_DISPATCH
{
    void* netevent_dispatch;
} NETEVENT_NPI_CLIENT_DISPATCH, *PNETEVENT_NPI_CLIENT_DISPATCH;
