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

#include "ebpf_ext.h"

// Dynamically compose the name of the register and unregister functions, using the provider name.

#define CONCATENATE_STRING(x, y) x##y

#define ebpf_ext_custom_register_providers(PROVIDER_NAME) CONCATENATE_STRING(ebpf_ext_register_, PROVIDER_NAME)
#define ebpf_ext_custom_unregister_providers(PROVIDER_NAME) CONCATENATE_STRING(ebpf_ext_unregister_, PROVIDER_NAME)

NTSTATUS ebpf_ext_custom_register_providers(PROVIDER_NAME)();
void ebpf_ext_custom_unregister_providers(PROVIDER_NAME)();

static bool _ebpf_process_providers_registered = false;

NTSTATUS
ebpf_ext_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    EBPF_EXT_LOG_ENTRY();

    status = ebpf_ext_custom_register_providers(PROVIDER_NAME)();
    if (!NT_SUCCESS(status)) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "ebpf_ext_process_register_providers failed.",
            status);
        goto Exit;
    }
    _ebpf_process_providers_registered = true;

Exit:
    if (!NT_SUCCESS(status)) {
        ebpf_ext_custom_unregister_providers(PROVIDER_NAME)();
    }
    EBPF_EXT_RETURN_NTSTATUS(status);
}

void
ebpf_ext_unregister_providers()
{
    if (_ebpf_process_providers_registered) {
        ebpf_ext_custom_unregister_providers(PROVIDER_NAME)();
        _ebpf_process_providers_registered = false;
    }
}
