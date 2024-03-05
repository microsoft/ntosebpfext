// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/*++

Abstract:

   This file implements the classifyFn, notifyFn, and flowDeleteFn callouts
   functions for:
   Layer 2 network receive
   Resource Acquire
   Resource Release

Environment:

    Kernel mode

--*/

#include "ntos_ebpf_ext.h"
#include "ntos_ebpf_ext_process.h"

static bool _ntos_ebpf_process_providers_registered = false;

NTSTATUS
ntos_ebpf_ext_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    NTOS_EBPF_EXT_LOG_ENTRY();

    status = ntos_ebpf_ext_process_register_providers();
    if (!NT_SUCCESS(status)) {
        NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NTOS_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NTOS_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "ntos_ebpf_ext_process_register_providers failed.",
            status);
        goto Exit;
    }
    _ntos_ebpf_process_providers_registered = true;

Exit:
    if (!NT_SUCCESS(status)) {
        ntos_ebpf_ext_unregister_providers();
    }
    NTOS_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
ntos_ebpf_ext_unregister_providers()
{
    if (_ntos_ebpf_process_providers_registered) {
        ntos_ebpf_ext_process_unregister_providers();
        _ntos_ebpf_process_providers_registered = false;
    }
}
