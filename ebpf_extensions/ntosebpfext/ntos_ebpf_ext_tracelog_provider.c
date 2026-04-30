// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file provides the TRACELOGGING_DEFINE_PROVIDER definition required by
// the common tracelogging implementation in ebpf-extension-common.
// NtosEbpfExt uses its own provider name and GUID, separate from other extensions.

#include "ebpf_ext_tracelog.h"

TRACELOGGING_DEFINE_PROVIDER(
    ebpf_ext_tracelog_provider,
    "NtosEbpfExtProvider",
    (0xd15cc421, 0xe9e4, 0x459b, 0x87, 0xa6, 0xb4, 0x5b, 0x7d, 0x84, 0xe9, 0xa8));
