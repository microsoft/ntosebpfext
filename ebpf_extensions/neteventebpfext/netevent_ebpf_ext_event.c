// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This file implements the netevent event-monitor program type hook on eBPF for Windows.
 */

#include "ebpf_netevent_hooks.h"
#include "netevent_ebpf_ext_event.h"
#include "netevent_ebpf_ext_program_info.h"

#include <errno.h>

//
// Global variables.
//

// Define a dynamic event buffer for optimizing the event data copy.
static uint8_t* _event_buffer = NULL; ///< Event buffer for copying the event data.
static size_t _event_buffer_size =
    4096; ///< Initial size of the event buffer, which will be dynamically resized as needed.
EX_SPIN_LOCK _ebpf_netevent_push_event_lock;

// Define the GUID for the NetEvent NPI (must match the one of the provider)
const NPIID netevent_npiid = {0x2227e81a, 0x8d8b, 0x11d4, {0xab, 0xad, 0x00, 0x90, 0x27, 0x71, 0x9e, 0x09}};
// Define the client module's ID
const NPI_MODULEID netevent_client_module_id = {
    sizeof(NPI_MODULEID), MIT_GUID, {0x8a9a5ef1, 0x2aa1, 0x42e9, {0x89, 0x5, 0xd1, 0xcf, 0x6, 0xc5, 0x77, 0x64}}};

//
// Prototypes.
//
static ebpf_result_t
_ebpf_netevent_program_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

static void
_ebpf_netevent_program_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

static void
_ebpf_netevent_push_event(_In_ netevent_event_md_t* netevent_event);

NTSTATUS
_netevent_ebpf_extension_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ PNPI_REGISTRATION_INSTANCE provider_registration_instance);

NTSTATUS
_netevent_ebpf_extension_detach_provider(_In_ HANDLE nmr_binding_handle);

//
// Structures for attaching to NetEvent (as an NMR client)
//

typedef struct netevent_ext_header
{
    uint16_t version; ///< Version of the extension data structure.
    size_t size;      ///< Size of the netevent function addresses structure.
} netevent_ext_header_t;

// This is the type definition for the netevent helper function addresses.
// This type should be matched by the Netevent NMI provider.
typedef struct netevent_ext_function_addresses
{
    netevent_ext_header_t header;
    netevent_capture_type_t capture_type;
    uint32_t helper_function_count;
    uint64_t* helper_function_address;
} netevent_ext_function_addresses_t;

// Dispatch table for the client module's helper functions
static const void* _ebpf_netevent_ext_helper_functions[] = {(void*)&_ebpf_netevent_push_event};
netevent_ext_function_addresses_t _netevent_client_dispatch = {
    .header = {.version = EBPF_NETEVENT_EXTENSION_VERSION, .size = sizeof(netevent_ext_function_addresses_t)},
    .capture_type = NetevenCapture_Drop,
    .helper_function_count = EBPF_COUNT_OF(_ebpf_netevent_ext_helper_functions),
    .helper_function_address = (uint64_t*)_ebpf_netevent_ext_helper_functions};

// Context structure for the client module's registration
typedef struct CLIENT_REGISTRATION_CONTEXT_
{
    HANDLE client_registration_handle;

} CLIENT_REGISTRATION_CONTEXT, *PCLIENT_REGISTRATION_CONTEXT;
static CLIENT_REGISTRATION_CONTEXT _netevent_client_registration_context = {.client_registration_handle = NULL};

// Context structure for the client module's binding to a provider module
typedef struct CLIENT_BINDING_CONTEXT_
{
    HANDLE nmr_binding_handle;
    void* client_context;
    void* provider_binding_context;
    const void* provider_dispatch;
    PNPI_REGISTRATION_INSTANCE provider_registration_instance;
} CLIENT_BINDING_CONTEXT, *PCLIENT_BINDING_CONTEXT;
CLIENT_BINDING_CONTEXT _netevent_client_binding_context = {
    .nmr_binding_handle = NULL,
    .client_context = NULL,
    .provider_binding_context = NULL,
    .provider_dispatch = NULL,
    .provider_registration_instance = NULL};

// Structure for the extension NMR client module's characteristics
const NPI_CLIENT_CHARACTERISTICS _netevent_client_characteristics = {
    0,
    sizeof(NPI_CLIENT_CHARACTERISTICS),
    _netevent_ebpf_extension_attach_provider, // Called by NMR after the client module has registered with NMR.
    _netevent_ebpf_extension_detach_provider,
    NULL,
    {0, sizeof(NPI_REGISTRATION_INSTANCE), &netevent_npiid, &netevent_client_module_id, 0, NULL}};

//
//  NMR client attach/detach callbacks functions to NetEvent as a provider
//
NTSTATUS
_netevent_ebpf_extension_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ PNPI_REGISTRATION_INSTANCE provider_registration_instance)
{
    EBPF_EXT_LOG_ENTRY();
    NTSTATUS status;

    UNREFERENCED_PARAMETER(client_context);
    UNREFERENCED_PARAMETER(provider_registration_instance);

    if (provider_registration_instance->NpiSpecificCharacteristics == NULL) {
        status = STATUS_NOINTERFACE;
        EBPF_EXT_LOG_MESSAGE(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_NETEVENT,
            "Incompatible netevent provider version");
        goto Exit;
    }

    // Attach to the NetEvent provider module.
    status = NmrClientAttachProvider(
        nmr_binding_handle,
        &_netevent_client_binding_context,
        &_netevent_client_dispatch,
        &_netevent_client_binding_context.provider_binding_context,
        &_netevent_client_binding_context.provider_dispatch);
    if (!NT_SUCCESS(status)) {
        EBPF_EXT_LOG_NTSTATUS_API_FAILURE(EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "NmrRegisterProvider", status);
        goto Exit;
    }

Exit:
    EBPF_EXT_RETURN_NTSTATUS(status);
}

NTSTATUS
_netevent_ebpf_extension_detach_provider(_In_ HANDLE nmr_binding_handle)
{
    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(nmr_binding_handle);
    // neteventebpfext does not maintain any state for the provider, therefore no action needed here.

    EBPF_EXT_RETURN_NTSTATUS(STATUS_SUCCESS);
}

//
// Event Hook NPI Provider.
//
ebpf_attach_provider_data_t _netevent_ebpf_netevent_event_hook_provider_data = {
    .header =
        {.version = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION, .size = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE},
    .supported_program_type = EBPF_PROGRAM_TYPE_NETEVENT_GUID,
    .bpf_attach_type = (bpf_attach_type_t)BPF_ATTACH_TYPE_NETEVENT};
ebpf_extension_data_t _netevent_ebpf_extension_netevent_event_hook_provider_data = {
    .header =
        {.version = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION, .size = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE},
    .data = &_netevent_ebpf_netevent_event_hook_provider_data};
NPI_MODULEID DECLSPEC_SELECTANY _ebpf_netevent_event_hook_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};
static ebpf_extension_hook_provider_t* _ebpf_netevent_event_hook_provider_context = NULL;
EX_PUSH_LOCK _ebpf_netevent_event_hook_provider_lock;
bool _ebpf_netevent_event_hook_provider_registered = FALSE;
uint64_t _ebpf_netevent_event_hook_provider_registration_count = 0;

//
// Event Program Information NPI Provider.
//
static ebpf_program_data_t _ebpf_netevent_event_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_netevent_event_program_info,
    .program_type_specific_helper_function_addresses = NULL, // No helper functions exposed to client eBPF programs.
    .context_create = _ebpf_netevent_program_context_create,
    .context_destroy = _ebpf_netevent_program_context_destroy,
    .required_irql = PASSIVE_LEVEL,
    .capabilities = {.supports_context_header = true},
};
static ebpf_extension_data_t _ebpf_netevent_event_program_info_provider_data = {
    .header = {EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_netevent_event_program_data)},
    .data = &_ebpf_netevent_event_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_netevent_event_program_info_provider_moduleid = {
    sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ebpf_extension_program_info_provider_t* _ebpf_netevent_event_program_info_provider_context = NULL;

//
// Event Hook NPI Client Attach and Detach Callbacks (to NetEvent NPI provider).
// Callbacks invoked when a Program Information NPI client attaches/detaches.
// (must register a separate Hook NPI provider module for each supported attach type)
//
static ebpf_result_t
_netevent_ebpf_extension_netevent_on_client_attach(
    _In_ const ebpf_extension_hook_client_t* attaching_client,
    _In_ const ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    bool push_lock_acquired = false;
    netevent_attach_opts_t* attach_opts;
    const ebpf_extension_data_t* client_data = ebpf_extension_hook_client_get_client_data(attaching_client);

    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(provider_context);

    if (client_data != NULL && client_data->data != NULL) {
        attach_opts = (netevent_attach_opts_t*)client_data->data;
        if ((attach_opts->capture_type >= NeteventCapture_All) && (attach_opts->capture_type <= NetevenCapture_None)) {
            _netevent_client_dispatch.capture_type = attach_opts->capture_type;
        } else {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_NETEVENT,
                "Incorrect capture type in attach opts.");
            result = EBPF_OPERATION_NOT_SUPPORTED;
            goto Exit;
        }
    }

    ExAcquirePushLockExclusive(&_ebpf_netevent_event_hook_provider_lock);
    push_lock_acquired = true;

    if (!_ebpf_netevent_event_hook_provider_registered) {
        // Register and attach the neteventebpfext extension to NetEvent as an NMR Client.
        // This will invoke the _netevent_ebpf_extension_attach_provider() callback.
        NTSTATUS status = NmrRegisterClient(
            &_netevent_client_characteristics,
            &_netevent_client_registration_context,
            &_netevent_client_binding_context.nmr_binding_handle);
        if (!NT_SUCCESS(status)) {
            EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_NETEVENT, "Attach to netevent failed", status);
            result = EBPF_OPERATION_NOT_SUPPORTED;
            goto Exit;
        }
        _ebpf_netevent_event_hook_provider_registered = TRUE;
    }

    _ebpf_netevent_event_hook_provider_registration_count++;

Exit:
    if (push_lock_acquired) {
        ExReleasePushLockExclusive(&_ebpf_netevent_event_hook_provider_lock);
    }

    EBPF_EXT_RETURN_RESULT(result);
}

static void
_netevent_ebpf_extension_netevent_on_client_detach(_In_ const ebpf_extension_hook_client_t* detaching_client)
{
    ebpf_result_t result = EBPF_SUCCESS;

    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(detaching_client);

    // Unregister the netevent create notify routine.
    ExAcquirePushLockExclusive(&_ebpf_netevent_event_hook_provider_lock);

    _ebpf_netevent_event_hook_provider_registration_count--;

    if (_ebpf_netevent_event_hook_provider_registered && _ebpf_netevent_event_hook_provider_registration_count == 0) {
        // Detach the neteventebpfext extension from NetEvent as an NMR Client.
        // This will invoke the _netevent_ebpf_extension_detach_provider() callback.
        NTSTATUS status = NmrDeregisterClient(_netevent_client_binding_context.nmr_binding_handle);
        if (!NT_SUCCESS(status)) {
            EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_NETEVENT,
                "Detach from netevent failed",
                status);
            result = EBPF_OPERATION_NOT_SUPPORTED;
        }
        _ebpf_netevent_event_hook_provider_registered = FALSE;
    }

    ExReleasePushLockExclusive(&_ebpf_netevent_event_hook_provider_lock);

    EBPF_EXT_LOG_EXIT();
}

//
// NMR registration/unregistration helpers.
//
NTSTATUS
ebpf_ext_register_netevent()
{
    NTSTATUS status = STATUS_SUCCESS;

    EBPF_EXT_LOG_ENTRY();

    const ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_netevent_event_program_info_provider_moduleid, &_ebpf_netevent_event_program_data};
    const ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_netevent_event_hook_provider_moduleid, &_netevent_ebpf_netevent_event_hook_provider_data};

    // Set the program type as the provider module id.
    _ebpf_netevent_event_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_NETEVENT;
    status = ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_netevent_event_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_NETEVENT,
            "ebpf_extension_program_info_provider_register",
            status);
        goto Exit;
    }

    _netevent_ebpf_netevent_event_hook_provider_data.supported_program_type = EBPF_PROGRAM_TYPE_NETEVENT;
    // Set the attach type as the provider module id.
    _ebpf_netevent_event_hook_provider_moduleid.Guid = EBPF_ATTACH_TYPE_NETEVENT;
    _netevent_ebpf_netevent_event_hook_provider_data.bpf_attach_type =
        (bpf_attach_type_t)_ebpf_netevent_event_section_info->bpf_attach_type;
    _netevent_ebpf_netevent_event_hook_provider_data.link_type = BPF_LINK_TYPE_PLAIN;
    status = ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        _netevent_ebpf_extension_netevent_on_client_attach,
        _netevent_ebpf_extension_netevent_on_client_detach,
        NULL,
        &_ebpf_netevent_event_hook_provider_context);
    if (status != EBPF_SUCCESS) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_NETEVENT,
            "ebpf_extension_hook_provider_register",
            status);
        goto Exit;
    }

    // Initialize the global event buffer.
    _event_buffer =
        (uint8_t*)ExAllocatePoolUninitialized(NonPagedPoolNx, _event_buffer_size, EBPF_NETEVENT_EXTENSION_POOL_TAG);
    if (_event_buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_NETEVENT,
            "Insufficient memory initializing the event buffer",
            status);
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        ebpf_ext_unregister_netevent();
    }
    EBPF_EXT_RETURN_NTSTATUS(status);
}

void
ebpf_ext_unregister_netevent()
{
    if (_ebpf_netevent_event_hook_provider_context) {
        ebpf_extension_hook_provider_unregister(_ebpf_netevent_event_hook_provider_context);
        _ebpf_netevent_event_hook_provider_context = NULL;
    }
    if (_ebpf_netevent_event_program_info_provider_context) {
        ebpf_extension_program_info_provider_unregister(_ebpf_netevent_event_program_info_provider_context);
        _ebpf_netevent_event_program_info_provider_context = NULL;
    }
    if (_event_buffer) {
        ExFreePool(_event_buffer);
        _event_buffer = NULL;
    }
}

//
// Event Hook NPI client helper functions (invoked by NetEvent as the NPI provider).
//
typedef struct _netevent_event_notify_context
{
    EBPF_CONTEXT_HEADER;
    netevent_event_md_t netevent_event_md;
} netevent_event_notify_context_t;

//
// eBPF NetEvent Program Information NPI helper routines.
//
static ebpf_result_t
_ebpf_netevent_program_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    EBPF_EXT_LOG_ENTRY();
    ebpf_result_t result;
    netevent_event_notify_context_t* netevent_event_context = NULL;

    if (context_in == NULL || context_size_in < sizeof(netevent_event_md_t)) {
        EBPF_EXT_LOG_MESSAGE(
            EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_NETEVENT, "Input Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (context == NULL) {
        EBPF_EXT_LOG_MESSAGE(
            EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_NETEVENT, "Output Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    *context = NULL;

    // Allocate memory for the context.
    netevent_event_context = (netevent_event_notify_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(netevent_event_notify_context_t), EBPF_NETEVENT_EXTENSION_POOL_TAG);
    EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        EBPF_EXT_TRACELOG_KEYWORD_NETEVENT, netevent_event_context, "netevent_event_context", result);

    // Copy the context from the caller.
    memcpy(&netevent_event_context->netevent_event_md, context_in, sizeof(netevent_event_md_t));

    // Copy the event's pointer & size from the caller, to the out context.
    netevent_event_context->netevent_event_md.event_data_start = (uint8_t*)data_in;
    netevent_event_context->netevent_event_md.event_data_end = (uint8_t*)data_in + data_size_in;
    *context = &netevent_event_context->netevent_event_md;
    netevent_event_context = NULL;
    result = EBPF_SUCCESS;

Exit:
    if (netevent_event_context) {
        ExFreePool(netevent_event_context);
        netevent_event_context = NULL;
    }
    EBPF_EXT_RETURN_RESULT(result);
}

static void
_ebpf_netevent_program_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    EBPF_EXT_LOG_ENTRY();
    netevent_event_notify_context_t* netevent_event_context = NULL;
    netevent_event_md_t* netevent_event_context_out = NULL;

    if (!context) {
        goto Exit;
    }

    netevent_event_context = CONTAINING_RECORD(context, netevent_event_notify_context_t, netevent_event_md);
    netevent_event_context_out = (netevent_event_md_t*)context_out;

    if (context_out != NULL && *context_size_out >= sizeof(netevent_event_md_t)) {
        // Copy the context to the caller.
        memcpy(netevent_event_context_out, &netevent_event_context->netevent_event_md, sizeof(netevent_event_md_t));

        // Zero out the event context info.
        netevent_event_context_out->event_data_start = 0;
        netevent_event_context_out->event_data_end = 0;
        *context_size_out = sizeof(netevent_event_md_t);
    } else {
        *context_size_out = 0;
    }

    // Copy the event data to 'data_out'.
    if (data_out != NULL && *data_size_out >= (size_t)(netevent_event_context->netevent_event_md.event_data_end -
                                                       netevent_event_context->netevent_event_md.event_data_start)) {
        memcpy(
            data_out,
            netevent_event_context->netevent_event_md.event_data_start,
            netevent_event_context->netevent_event_md.event_data_end -
                netevent_event_context->netevent_event_md.event_data_start);
        *data_size_out = netevent_event_context->netevent_event_md.event_data_end -
                         netevent_event_context->netevent_event_md.event_data_start;
    } else {
        *data_size_out = 0;
    }

    ExFreePool(netevent_event_context);

Exit:
    EBPF_EXT_LOG_EXIT();
}

void
_ebpf_netevent_push_event(_In_ netevent_event_md_t* netevent_event)
{
    // Logging may delay the event processing, consider enabling only for debugging or if the calling frequency for a
    // specific use case is low.
    // EBPF_EXT_LOG_ENTRY();

    if (netevent_event == NULL) {
        return;
    }

    ebpf_result_t result;
    ebpf_extension_hook_client_t* client_context = NULL;
    netevent_event_notify_context_t netevent_event_notify_context = {0};
    uint64_t event_size = netevent_event->event_data_end - netevent_event->event_data_start;
    bool spin_lock_acquired = false;

    // Currently, the verifier does not support read-only contexts, so we need to copy the event data, rather than
    // directly passing the existing pointers.
    // Verifier feature proposal: https://github.com/vbpf/ebpf-verifier/issues/639
    KIRQL oldIrql = ExAcquireSpinLockExclusive(&_ebpf_netevent_push_event_lock);
    spin_lock_acquired = true;
    if (event_size > _event_buffer_size) {
        // If the event buffer is too small, attempt to resize it.
        uint8_t* new_event_buffer =
            (uint8_t*)ExAllocatePoolUninitialized(NonPagedPoolNx, event_size, EBPF_NETEVENT_EXTENSION_POOL_TAG);
        if (new_event_buffer == NULL) {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_NETEVENT,
                "Failed to resize the event buffer - event lost");
            goto Exit;
        }
        if (_event_buffer) {
            ExFreePool(_event_buffer);
        }
        _event_buffer = new_event_buffer;
        _event_buffer_size = event_size;
    }
    memcpy(_event_buffer, netevent_event->event_data_start, event_size);
    netevent_event_notify_context.netevent_event_md.event_data_start = _event_buffer;
    netevent_event_notify_context.netevent_event_md.event_data_end = _event_buffer + event_size;

    // For each attached client call the netevent hook.
    client_context = ebpf_extension_hook_get_next_attached_client(_ebpf_netevent_event_hook_provider_context, NULL);
    while (client_context != NULL) {
        NTSTATUS status = 0;
        if (ebpf_extension_hook_client_enter_rundown(client_context)) {
            result = ebpf_extension_hook_invoke_program(
                client_context, &netevent_event_notify_context.netevent_event_md, (uint32_t*)&status);
            if (result != EBPF_SUCCESS) {
                EBPF_EXT_LOG_MESSAGE_GUID_STATUS(
                    EBPF_EXT_TRACELOG_LEVEL_ERROR,
                    EBPF_EXT_TRACELOG_KEYWORD_NETEVENT,
                    "netevent_ebpf_extension_hook_invoke_program failed module ",
                    ebpf_extension_hook_provider_get_client_module_id(client_context),
                    status);
            }
            ebpf_extension_hook_client_leave_rundown(client_context);
        } else {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_NETEVENT,
                "netevent_ebpf_extension_hook_client_enter_rundown failed");
        }
        client_context =
            ebpf_extension_hook_get_next_attached_client(_ebpf_netevent_event_hook_provider_context, client_context);
    }

Exit:
    if (spin_lock_acquired) {
        ExReleaseSpinLockExclusive(&_ebpf_netevent_push_event_lock, oldIrql);
    }

    // EBPF_EXT_LOG_EXIT();
}
