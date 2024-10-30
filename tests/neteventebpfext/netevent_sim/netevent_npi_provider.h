// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

// Define the NPI version and provider characteristics version
#define NPI_CURRENT_CLIENT_REVISION 1
#define NPI_PROVIDER_CHARACTERISTICS_VERSION 1

// Define the GUID for the NetEvent NPI
const NPIID netevent_npiid = {0x2227e81a, 0x8d8b, 0x11d4, {0xab, 0xad, 0x00, 0x90, 0x27, 0x71, 0x9e, 0x09}};

// Define the provider module's identification
const NPI_MODULEID netevent_module_id = {
    sizeof(NPI_MODULEID), MIT_GUID, {0x463f69c5, 0x5871, 0x4a8c, {0xb3, 0xc8, 0x5, 0x69, 0x33, 0xc3, 0xc0, 0xec}}};

// Define th context structure for the provider module's registration
typedef struct PROVIDER_REGISTRATION_CONTEXT_
{
    HANDLE provider_registration_handle; // Registration handle
} PROVIDER_REGISTRATION_CONTEXT;

// Define the context structure for the provider module's binding to a client module
typedef struct PROVIDER_BINDING_CONTEXT_
{
    HANDLE client_binding_handle;                            // Handle of the attached client
    const ebpf_helper_function_addresses_t* client_dispatch; // Dispatch routines addresses of the attached client
    PNPI_REGISTRATION_INSTANCE client_registration_instance; // Registration instance of the attached client
    void* client_binding_context;                            // Binding context of the attached client
} PROVIDER_BINDING_CONTEXT;
