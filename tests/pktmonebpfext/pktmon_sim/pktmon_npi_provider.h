// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

// Define the NPI version and provider characteristics version
#define NPI_CURRENT_CLIENT_REVISION 1
#define NPI_PROVIDER_CHARACTERISTICS_VERSION 1

// Define the GUID for the PktMon NPI
const NPIID pktmon_npiid = {0xcd3d4424, 0x657e, 0x404c, {0x87, 0xb2, 0xac, 0xf9, 0x28, 0x2c, 0xdd, 0x82}};

// Define the provider module's identification
const NPI_MODULEID pktmon_module_id = {
    sizeof(NPI_MODULEID), MIT_GUID, {0x463f69c5, 0x5871, 0x4a8c, {0xb3, 0xc8, 0x5, 0x69, 0x33, 0xc3, 0xc0, 0xec}}};

// Define the provider characteristics structure
typedef struct PKTMON_NPI_PROVIDER_CHARACTERISTICS_
{
    int dummy; // The provider module's specific characteristics can be added here (none for now)

} PKTMON_NPI_PROVIDER_CHARACTERISTICS, *PPKTMON_NPI_PROVIDER_CHARACTERISTICS;

// Define th context structure for the provider module's registration
typedef struct PROVIDER_REGISTRATION_CONTEXT_
{
    HANDLE provider_registration_handle; // Registration handle (TBD)
} PROVIDER_REGISTRATION_CONTEXT, *PPROVIDER_REGISTRATION_CONTEXT;

// Define the context structure for the provider module's binding to a client module
typedef struct PROVIDER_BINDING_CONTEXT_
{
    HANDLE client_binding_handle;                            // Handle of the attached client
    CONST PKTMON_NPI_CLIENT_DISPATCH* client_dispatch;       // Dispatch routines of the attached client
    PNPI_REGISTRATION_INSTANCE client_registration_instance; // Registration instance of the attached client
    PVOID client_binding_context;                            // Binding context of the attached client
} PROVIDER_BINDING_CONTEXT, *PPROVIDER_BINDING_CONTEXT;
