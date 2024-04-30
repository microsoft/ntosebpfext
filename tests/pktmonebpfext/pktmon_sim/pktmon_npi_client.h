// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

typedef struct
{
    unsigned char* event_data; ///< Data associated with the event.
    size_t event_data_length;  ///< Length of the event data.
} pktmon_event_info_t;

// Define the NPI client dispatch table
typedef struct _PKTMON__NPI_CLIENT_DISPATCH
{
    VOID (*pktmon_push_event)(HANDLE, pktmon_event_info_t, size_t);
} PKTMON_NPI_CLIENT_DISPATCH, *PPKTMON_NPI_CLIENT_DISPATCH;
