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

#include "net_ebpf_ext.h"
#include "net_ebpf_ext_process.h"

static bool _net_ebpf_process_providers_registered = false;

NTSTATUS
net_ebpf_ext_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    NET_EBPF_EXT_LOG_ENTRY();

    status = net_ebpf_ext_process_register_providers();
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "net_ebpf_ext_process_register_providers failed.",
            status);
        goto Exit;
    }
    _net_ebpf_process_providers_registered = true;

Exit:
    if (!NT_SUCCESS(status)) {
        net_ebpf_ext_unregister_providers();
    }
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_unregister_providers()
{
    if (_net_ebpf_process_providers_registered) {
        net_ebpf_ext_process_unregister_providers();
        _net_ebpf_process_providers_registered = false;
    }
}
