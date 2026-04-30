// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file provides the TRACELOGGING_DEFINE_PROVIDER definition required by
// the common tracelogging implementation in ebpf-extension-common.
// NeteventEbpfExt uses its own provider name and GUID, separate from NtosEbpfExt.

#include "ebpf_ext_tracelog.h"

TRACELOGGING_DEFINE_PROVIDER(
    ebpf_ext_tracelog_provider,
    "NeteventEbpfExtProvider",
    (0xbdd03353, 0x2c68, 0x4e7d, 0xae, 0x3a, 0xc0, 0x07, 0x90, 0x93, 0x01, 0x88));
