// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This file implements the pktmon event-monitor program type hook on eBPF for Windows.
 */

#include "ebpf_pktmon_hooks.h"
#include "pktmon_ebpf_ext_event.h"
#include "pktmon_ebpf_ext_program_info.h"

#include <errno.h>

//
// Prototypes.
//
static ebpf_result_t
_ebpf_pktmon_program_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

static void
_ebpf_pktmon_program_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

static void
_ebpf_pktmon_push_event(_In_ pktmon_event_md_t* pktmon_event);

//
// Global variables.
///
static HANDLE _pktmon_client_handle;
// Define the GUID for the PktMon NPI (mist match the one of the provider)
const NPIID pktmon_npiid = {0xcd3d4424, 0x657e, 0x404c, {0x87, 0xb2, 0xac, 0xf9, 0x28, 0x2c, 0xdd, 0x82}};
// Define the client module's identification
const NPI_MODULEID pktmon_client_module_id = {
    sizeof(NPI_MODULEID), MIT_GUID, {0x8a9a5ef1, 0x2aa1, 0x42e9, {0x89, 0x5, 0xd1, 0xcf, 0x6, 0xc5, 0x77, 0x64}}};

static const void* _ebpf_pktmon_ext_helper_functions[] = {(void*)&_ebpf_pktmon_push_event};

static ebpf_helper_function_addresses_t _ebpf_pktmon_event_helper_function_address_table = {
    .header =
        {.version = EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION,
         .size = EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_SIZE},
    .helper_function_count = EBPF_COUNT_OF(_ebpf_pktmon_ext_helper_functions),
    .helper_function_address = (uint64_t*)_ebpf_pktmon_ext_helper_functions};

// Context structure for the client module's registration
typedef struct CLIENT_REGISTRATION_CONTEXT_
{
    // Client-specific members
    HANDLE client_registration_handle; // Registration handle (TBD)

} CLIENT_REGISTRATION_CONTEXT, *PCLIENT_REGISTRATION_CONTEXT;
static CLIENT_REGISTRATION_CONTEXT _pktmon_client_registration_context = {
    .client_registration_handle = NULL
    // TBD: Add any other client-specific information here
};

// Structure for the client module's NPI-specific characteristics
// typedef struct PKTMON_CLIENT_CHARACTERISTICS_ {
//    // The NPI-specific characteristics of the client module
//    int dummy;
//} PKTMON_CLIENT_CHARACTERISTICS, PPKTMON_CLIENT_CHARACTERISTICS;
// const PKTMON_CLIENT_CHARACTERISTICS _pktmon_client_characteristics = {0};

typedef struct PKTMON_NPI_CLIENT_CHARACTERISTICS_
{
    int dummy; // The client module's specific characteristics can be added here (none for now)

} PKTMON_NPI_CLIENT_CHARACTERISTICS, *PPKTMON_NPI_CLIENT_CHARACTERISTICS;
const PKTMON_NPI_CLIENT_CHARACTERISTICS _pktmon_client_specific_characteristics = {0};

NTSTATUS
_pktmon_ebpf_extension_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ PVOID client_context,
    _In_ PNPI_REGISTRATION_INSTANCE provider_registration_instance)
{
    UNREFERENCED_PARAMETER(nmr_binding_handle);
    UNREFERENCED_PARAMETER(client_context);
    UNREFERENCED_PARAMETER(provider_registration_instance);

    return STATUS_SUCCESS;
}

NTSTATUS
_pktmon_ebpf_extension_detach_provider(_In_ HANDLE nmr_binding_handle)
{
    UNREFERENCED_PARAMETER(nmr_binding_handle);

    return STATUS_SUCCESS;
}

// Structure for the extension NMR client module's characteristics
const NPI_CLIENT_CHARACTERISTICS _pktmon_client_characteristics = {
    0,
    sizeof(NPI_CLIENT_CHARACTERISTICS),
    _pktmon_ebpf_extension_attach_provider,
    _pktmon_ebpf_extension_detach_provider,
    NULL,
    {0,
     sizeof(NPI_REGISTRATION_INSTANCE),
     &pktmon_npiid,
     &pktmon_client_module_id,
     0,
     &_pktmon_client_specific_characteristics}};

//
// Event Hook NPI Provider.
//
ebpf_attach_provider_data_t _pktmon_ebpf_pktmon_event_hook_provider_data = {
    .header =
        {.version = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION, .size = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE},
    .supported_program_type = EBPF_PROGRAM_TYPE_PKTMON_GUID,
    .bpf_attach_type = (bpf_attach_type_t)BPF_ATTACH_TYPE_PKTMON};
ebpf_extension_data_t _pktmon_ebpf_extension_pktmon_event_hook_provider_data = {
    .header =
        {.version = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION, .size = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE},
    .data = &_pktmon_ebpf_pktmon_event_hook_provider_data};
NPI_MODULEID DECLSPEC_SELECTANY _ebpf_pktmon_event_hook_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};
static ebpf_extension_hook_provider_t* _ebpf_pktmon_event_hook_provider_context = NULL;
EX_PUSH_LOCK _ebpf_pktmon_event_hook_provider_lock;
bool _ebpf_pktmon_event_hook_provider_registered = FALSE;
uint64_t _ebpf_pktmon_event_hook_provider_registration_count = 0;

//
// Event Program Information NPI Provider.
//
static ebpf_program_data_t _ebpf_pktmon_event_program_data = {
    .header = {.version = EBPF_PROGRAM_DATA_CURRENT_VERSION, .size = EBPF_PROGRAM_DATA_CURRENT_VERSION_SIZE},
    .program_info = &_ebpf_pktmon_event_program_info,
    .program_type_specific_helper_function_addresses = &_ebpf_pktmon_event_helper_function_address_table,
    .context_create = _ebpf_pktmon_program_context_create,
    .context_destroy = _ebpf_pktmon_program_context_destroy,
    .required_irql = PASSIVE_LEVEL,
};
static ebpf_extension_data_t _ebpf_pktmon_event_program_info_provider_data = {
    EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_pktmon_event_program_data), &_ebpf_pktmon_event_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_pktmon_event_program_info_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ebpf_extension_program_info_provider_t* _ebpf_pktmon_event_program_info_provider_context = NULL;

//
// Event Hook NPI Client Attach and Detach Callbacks (to PktMon NPI provider).
// Callbacks invoked when a Program Information NPI client attaches/detaches.
// (must register a separate Hook NPI provider module for each supported attach type)
//
static ebpf_result_t
_pktmon_ebpf_extension_pktmon_event_on_client_attach(
    _In_ const ebpf_extension_hook_client_t* attaching_client,
    _In_ const ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    bool push_lock_acquired = false;

    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(attaching_client);
    UNREFERENCED_PARAMETER(provider_context);

    ExAcquirePushLockExclusive(&_ebpf_pktmon_event_hook_provider_lock);

    push_lock_acquired = true;

    if (!_ebpf_pktmon_event_hook_provider_registered) {
        // TBD: Register and attach the pktmonebpfext extension to PktMon as an NMR Client
        NTSTATUS status = NmrRegisterClient(
            &_pktmon_client_characteristics, &_pktmon_client_registration_context, &_pktmon_client_handle);
        if (!NT_SUCCESS(status)) {
            EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_PKTMON, "Attach to pktmon failed", status);
            result = EBPF_OPERATION_NOT_SUPPORTED;
            goto Exit;
        }
        _ebpf_pktmon_event_hook_provider_registered = TRUE;
    }

    _ebpf_pktmon_event_hook_provider_registration_count++;

Exit:
    if (push_lock_acquired) {
        ExReleasePushLockExclusive(&_ebpf_pktmon_event_hook_provider_lock);
    }

    EBPF_EXT_RETURN_RESULT(result);
}

static void
_pktmon_ebpf_extension_pktmon_event_on_client_detach(_In_ const ebpf_extension_hook_client_t* detaching_client)
{
    ebpf_result_t result = EBPF_SUCCESS;

    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(detaching_client);

    // Unregister the pktmon create notify routine.
    ExAcquirePushLockExclusive(&_ebpf_pktmon_event_hook_provider_lock);

    _ebpf_pktmon_event_hook_provider_registration_count--;

    if (_ebpf_pktmon_event_hook_provider_registered && _ebpf_pktmon_event_hook_provider_registration_count == 0) {
        // TBD: Deregister the push event routine as an NMR Client
        NTSTATUS status = NmrDeregisterProvider(_pktmon_client_handle);
        if (!NT_SUCCESS(status)) {
            EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_PKTMON, "Detach from pktmon failed", status);
            result = EBPF_OPERATION_NOT_SUPPORTED;
        }
        _ebpf_pktmon_event_hook_provider_registered = FALSE;
    }

    ExReleasePushLockExclusive(&_ebpf_pktmon_event_hook_provider_lock);

    EBPF_EXT_LOG_EXIT();
}

//
// NMR registration/unregistration helpers.
//
NTSTATUS
ebpf_ext_register_pktmon()
{
    NTSTATUS status = STATUS_SUCCESS;

    EBPF_EXT_LOG_ENTRY();

    const ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_pktmon_event_program_info_provider_moduleid, &_ebpf_pktmon_event_program_data};
    const ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_pktmon_event_hook_provider_moduleid, &_pktmon_ebpf_pktmon_event_hook_provider_data};

    // Set the program type as the provider module id.
    _ebpf_pktmon_event_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_PKTMON;
    status = ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_pktmon_event_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_PKTMON,
            "ebpf_extension_program_info_provider_register",
            status);
        goto Exit;
    }

    _pktmon_ebpf_pktmon_event_hook_provider_data.supported_program_type = EBPF_PROGRAM_TYPE_PKTMON;
    // Set the attach type as the provider module id.
    _ebpf_pktmon_event_hook_provider_moduleid.Guid = EBPF_ATTACH_TYPE_PKTMON;
    _pktmon_ebpf_pktmon_event_hook_provider_data.bpf_attach_type =
        (bpf_attach_type_t)_ebpf_pktmon_event_section_info->bpf_attach_type;
    _pktmon_ebpf_pktmon_event_hook_provider_data.link_type = BPF_LINK_TYPE_PLAIN;
    status = ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        _pktmon_ebpf_extension_pktmon_event_on_client_attach,
        _pktmon_ebpf_extension_pktmon_event_on_client_detach,
        NULL,
        &_ebpf_pktmon_event_hook_provider_context);
    if (status != EBPF_SUCCESS) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_PKTMON,
            "ebpf_extension_hook_provider_register",
            status);
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        ebpf_ext_unregister_pktmon();
    }
    EBPF_EXT_RETURN_NTSTATUS(status);
}

void
ebpf_ext_unregister_pktmon()
{
    if (_ebpf_pktmon_event_hook_provider_context) {
        ebpf_extension_hook_provider_unregister(_ebpf_pktmon_event_hook_provider_context);
        _ebpf_pktmon_event_hook_provider_context = NULL;
    }
    if (_ebpf_pktmon_event_program_info_provider_context) {
        ebpf_extension_program_info_provider_unregister(_ebpf_pktmon_event_program_info_provider_context);
        _ebpf_pktmon_event_program_info_provider_context = NULL;
    }
}

//
// eBPF PktMon Program Information NPI helper routines.
//
static ebpf_result_t
_ebpf_pktmon_program_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    EBPF_EXT_LOG_ENTRY();
    ebpf_result_t result;
    pktmon_event_md_t* pktmon_event_context = NULL;

    *context = NULL;

    if (context_in == NULL || context_size_in < sizeof(pktmon_event_md_t)) {
        EBPF_EXT_LOG_MESSAGE(EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_PKTMON, "Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Allocate memory for the context.
    pktmon_event_context = (pktmon_event_md_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(pktmon_event_md_t), EBPF_EXTENSION_POOL_TAG);
    EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        EBPF_EXT_TRACELOG_KEYWORD_PKTMON, pktmon_event_context, "pktmon_event_context", result);

    // Copy the context from the caller.
    memcpy(pktmon_event_context, context_in, sizeof(pktmon_event_md_t));

    // Copy the event's pointer & size from the caller, to the out context.
    pktmon_event_context->event_data_start = (uint8_t*)data_in;
    pktmon_event_context->event_data_end = (uint8_t*)data_in + data_size_in;
    *context = pktmon_event_context;
    pktmon_event_context = NULL;
    result = EBPF_SUCCESS;

Exit:
    if (pktmon_event_context) {
        ExFreePool(pktmon_event_context);
        pktmon_event_context = NULL;
    }
    EBPF_EXT_RETURN_RESULT(result);
}

static void
_ebpf_pktmon_program_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    EBPF_EXT_LOG_ENTRY();

    pktmon_event_md_t* pktmon_event_context = (pktmon_event_md_t*)context;
    pktmon_event_md_t* pktmon_event_context_out = (pktmon_event_md_t*)context_out;

    if (!pktmon_event_context) {
        goto Exit;
    }

    if (context_out != NULL && *context_size_out >= sizeof(pktmon_event_md_t)) {
        // Copy the context to the caller.
        memcpy(pktmon_event_context_out, pktmon_event_context, sizeof(pktmon_event_md_t));
        *context_size_out = sizeof(pktmon_event_md_t);

        // Zero out the event context info.
        pktmon_event_context_out->event_data_start = 0;
        pktmon_event_context_out->event_data_end = 0;
        *context_size_out = sizeof(pktmon_event_md_t);
    } else {
        *context_size_out = 0;
    }

    // Copy the event data to 'data_out'.
    if (data_out != NULL &&
        *data_size_out >= (size_t)(pktmon_event_context->event_data_end - pktmon_event_context->event_data_start)) {
        memcpy(
            data_out,
            pktmon_event_context->event_data_start,
            pktmon_event_context->event_data_end - pktmon_event_context->event_data_start + 1);
        *data_size_out = pktmon_event_context->event_data_end - pktmon_event_context->event_data_start;
    } else {
        *data_size_out = 0;
    }

    ExFreePool(pktmon_event_context);

Exit:
    EBPF_EXT_LOG_EXIT();
}

//
// Event Hook NPI helper functions.
//
typedef struct _pktmon_event_notify_context
{
    pktmon_event_md_t pktmon_event_md;
} pktmon_event_notify_context_t;

void
_ebpf_pktmon_push_event(_In_ pktmon_event_md_t* pktmon_event)
{
    // TBD: logging may delay the event processing, consider removing.
    // EBPF_EXT_LOG_ENTRY();

    // Copy the event data to the context.
    pktmon_event_notify_context_t* pktmon_event_notify_context = (pktmon_event_notify_context_t*)pktmon_event;
    if (pktmon_event_notify_context != NULL) {

        pktmon_event_notify_context->pktmon_event_md.event_data_start = pktmon_event->event_data_start;
        pktmon_event_notify_context->pktmon_event_md.event_data_end = pktmon_event->event_data_end;
        memcpy(
            pktmon_event_notify_context->pktmon_event_md.event_data_start,
            pktmon_event->event_data_start,
            pktmon_event->event_data_end - pktmon_event->event_data_start + 1);

    } else {
        pktmon_event_notify_context->pktmon_event_md.event_data_start = 0;
        pktmon_event_notify_context->pktmon_event_md.event_data_end = 0;
    }

    // For each attached client call the pktmon hook.
    ebpf_result_t result;
    ebpf_extension_hook_client_t* client_context =
        ebpf_extension_hook_get_next_attached_client(_ebpf_pktmon_event_hook_provider_context, NULL);
    while (client_context != NULL) {
        NTSTATUS status = 0;
        if (ebpf_extension_hook_client_enter_rundown(client_context)) {
            result = ebpf_extension_hook_invoke_program(
                client_context, &pktmon_event_notify_context->pktmon_event_md, (uint32_t*)&status);
            if (result != EBPF_SUCCESS) {
                EBPF_EXT_LOG_MESSAGE(
                    EBPF_EXT_TRACELOG_LEVEL_ERROR,
                    EBPF_EXT_TRACELOG_KEYWORD_PKTMON,
                    "pktmon_ebpf_extension_hook_invoke_program failed");
            }
            ebpf_extension_hook_client_leave_rundown(client_context);
        } else {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_PKTMON,
                "pktmon_ebpf_extension_hook_client_enter_rundown failed");
        }
        // If the client returns a non-zero value, stop calling the other clients.
        if (!NT_SUCCESS(status) && pktmon_event) {
            break;
        }

        client_context =
            ebpf_extension_hook_get_next_attached_client(_ebpf_pktmon_event_hook_provider_context, client_context);
    }

    if (pktmon_event_notify_context->pktmon_event_md.event_data_start != NULL) {
        ExFreePool(pktmon_event_notify_context->pktmon_event_md.event_data_start);
    }

    // EBPF_EXT_LOG_EXIT();
}
