// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This file implements the process program type hook on eBPF for Windows.
 */

#include "ntos_ebpf_ext_process.h"

#include <errno.h>

static ebpf_result_t
_ebpf_process_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context);

static void
_ebpf_process_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out);

void
_ebpf_process_create_process_notify_routine_ex(
    _Inout_ PEPROCESS process, _In_ HANDLE process_id, _Inout_opt_ PPS_CREATE_NOTIFY_INFO create_info);

_Success_(return >= 0) static int32_t _ebpf_process_get_image_path(
    _In_ process_md_t* process_md, _Out_writes_bytes_(path_length) uint8_t* path, uint32_t path_length);

static const void* _ebpf_process_helper_functions[] = {(void*)&_ebpf_process_get_image_path};

static ebpf_helper_function_addresses_t _ebpf_process_helper_function_address_table = {
    .header = {EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION, EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_SIZE},
    .helper_function_count = EBPF_COUNT_OF(_ebpf_process_helper_functions),
    .helper_function_address = (uint64_t*)_ebpf_process_helper_functions,
};

//
// Process Program Information NPI Provider.
//
static ebpf_program_data_t _ebpf_process_program_data = {
    .header = {EBPF_PROGRAM_DATA_CURRENT_VERSION, EBPF_PROGRAM_DATA_CURRENT_VERSION_SIZE},
    .program_info = &_ebpf_process_program_info,
    .program_type_specific_helper_function_addresses = &_ebpf_process_helper_function_address_table,
    .context_create = _ebpf_process_context_create,
    .context_destroy = _ebpf_process_context_destroy,
    .required_irql = PASSIVE_LEVEL,
};

static ebpf_extension_data_t _ebpf_process_program_info_provider_data = {
    NTOS_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_process_program_data), &_ebpf_process_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_process_program_info_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ntos_ebpf_extension_program_info_provider_t* _ebpf_process_program_info_provider_context = NULL;

//
// Process Hook NPI Provider.
//
ebpf_attach_provider_data_t _ntos_ebpf_process_hook_provider_data = {
    .header = {EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION, EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE},
    .supported_program_type = EBPF_PROGRAM_TYPE_PROCESS_GUID,
    .bpf_attach_type = (bpf_attach_type_t)BPF_ATTACH_TYPE_PROCESS,
};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_process_hook_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ntos_ebpf_extension_hook_provider_t* _ebpf_process_hook_provider_context = NULL;

EX_PUSH_LOCK _ebpf_process_hook_provider_lock;
bool _ebpf_process_hook_provider_registered = FALSE;
uint64_t _ebpf_process_hook_provider_registration_count = 0;

//
// Client attach/detach handler routines.
//

static ebpf_result_t
_ntos_ebpf_extension_process_on_client_attach(
    _In_ const ntos_ebpf_extension_hook_client_t* attaching_client,
    _In_ const ntos_ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    bool push_lock_acquired = false;

    NTOS_EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(attaching_client);
    UNREFERENCED_PARAMETER(provider_context);

    ExAcquirePushLockExclusive(&_ebpf_process_hook_provider_lock);

    push_lock_acquired = true;

    if (!_ebpf_process_hook_provider_registered) {
        // Register the process create notify routine.
        NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(_ebpf_process_create_process_notify_routine_ex, FALSE);
        if (!NT_SUCCESS(status)) {
            NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                NTOS_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NTOS_EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
                "PsSetCreateProcessNotifyRoutineEx failed",
                status);
            result = EBPF_OPERATION_NOT_SUPPORTED;
            goto Exit;
        }
        _ebpf_process_hook_provider_registered = TRUE;
    }

    _ebpf_process_hook_provider_registration_count++;

Exit:
    if (push_lock_acquired) {
        ExReleasePushLockExclusive(&_ebpf_process_hook_provider_lock);
    }

    NTOS_EBPF_EXT_RETURN_RESULT(result);
}

static void
_ntos_ebpf_extension_process_on_client_detach(_In_ const ntos_ebpf_extension_hook_client_t* detaching_client)
{
    ebpf_result_t result = EBPF_SUCCESS;

    NTOS_EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(detaching_client);

    // Unregister the process create notify routine.
    ExAcquirePushLockExclusive(&_ebpf_process_hook_provider_lock);

    _ebpf_process_hook_provider_registration_count--;

    if (_ebpf_process_hook_provider_registered && _ebpf_process_hook_provider_registration_count == 0) {
        NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(_ebpf_process_create_process_notify_routine_ex, TRUE);
        if (!NT_SUCCESS(status)) {
            NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                NTOS_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NTOS_EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
                "PsSetCreateProcessNotifyRoutineEx failed",
                status);
            result = EBPF_OPERATION_NOT_SUPPORTED;
        }
        _ebpf_process_hook_provider_registered = FALSE;
    }

    ExReleasePushLockExclusive(&_ebpf_process_hook_provider_lock);

    NTOS_EBPF_EXT_LOG_EXIT();
}

//
// NMR Registration Helper Routines.
//

NTSTATUS
ntos_ebpf_ext_process_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    NTOS_EBPF_EXT_LOG_ENTRY();

    const ntos_ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_process_program_info_provider_moduleid, &_ebpf_process_program_data};
    const ntos_ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_process_hook_provider_moduleid, &_ntos_ebpf_process_hook_provider_data};

    // Set the program type as the provider module id.
    _ebpf_process_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_PROCESS;
    _ebpf_process_hook_provider_moduleid.Guid = EBPF_ATTACH_TYPE_PROCESS;
    status = ntos_ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_process_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NTOS_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NTOS_EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
            "ntos_ebpf_extension_program_info_provider_register",
            status);
        goto Exit;
    }

    status = ntos_ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        _ntos_ebpf_extension_process_on_client_attach,
        _ntos_ebpf_extension_process_on_client_detach,
        NULL,
        &_ebpf_process_hook_provider_context);
    if (status != EBPF_SUCCESS) {
        NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NTOS_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NTOS_EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
            "ntos_ebpf_extension_hook_provider_register",
            status);
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        ntos_ebpf_ext_process_unregister_providers();
    }
    NTOS_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
ntos_ebpf_ext_process_unregister_providers()
{
    if (_ebpf_process_hook_provider_context) {
        ntos_ebpf_extension_hook_provider_unregister(_ebpf_process_hook_provider_context);
        _ebpf_process_hook_provider_context = NULL;
    }
    if (_ebpf_process_program_info_provider_context) {
        ntos_ebpf_extension_program_info_provider_unregister(_ebpf_process_program_info_provider_context);
        _ebpf_process_program_info_provider_context = NULL;
    }
}

static ebpf_result_t
_ebpf_process_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    NTOS_EBPF_EXT_LOG_ENTRY();
    ebpf_result_t result;
    process_md_t* process_context = NULL;

    *context = NULL;

    if (context_in == NULL || context_size_in < sizeof(process_md_t)) {
        NTOS_EBPF_EXT_LOG_MESSAGE(
            NTOS_EBPF_EXT_TRACELOG_LEVEL_ERROR, NTOS_EBPF_EXT_TRACELOG_KEYWORD_PROCESS, "Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    process_context =
        (process_md_t*)ExAllocatePoolUninitialized(NonPagedPoolNx, sizeof(process_md_t), NTOS_EBPF_EXTENSION_POOL_TAG);
    NTOS_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        NTOS_EBPF_EXT_TRACELOG_KEYWORD_PROCESS, process_context, "process_context", result);

    // Copy the context from the caller.
    memcpy(process_context, context_in, sizeof(process_md_t));

    // Replace the process_id_start and process_id_end with pointers to data_in.
    process_context->command_start = (uint8_t*)data_in;
    process_context->command_end = (uint8_t*)data_in + data_size_in;

    *context = process_context;
    process_context = NULL;
    result = EBPF_SUCCESS;

Exit:
    if (process_context) {
        ExFreePool(process_context);
        process_context = NULL;
    }
    NTOS_EBPF_EXT_RETURN_RESULT(result);
}

static void
_ebpf_process_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    NTOS_EBPF_EXT_LOG_ENTRY();

    process_md_t* process_context = (process_md_t*)context;
    process_md_t* process_context_out = (process_md_t*)context_out;

    if (!process_context) {
        goto Exit;
    }

    if (context_out != NULL && *context_size_out >= sizeof(process_md_t)) {
        // Copy the context to the caller.
        memcpy(process_context_out, process_context, sizeof(process_md_t));

        // Zero out the command_start and command_end.
        process_context_out->command_start = 0;
        process_context_out->command_end = 0;
        *context_size_out = sizeof(process_md_t);
    } else {
        *context_size_out = 0;
    }

    // Copy the command to the data_out.
    if (data_out != NULL && *data_size_out >= (size_t)(process_context->command_end - process_context->command_start)) {
        memcpy(data_out, process_context->command_start, process_context->command_end - process_context->command_start);
        *data_size_out = process_context->command_end - process_context->command_start;
    } else {
        *data_size_out = 0;
    }

    ExFreePool(process_context);

Exit:
    NTOS_EBPF_EXT_LOG_EXIT();
}

typedef struct _process_notify_context
{
    process_md_t process_md;
    PEPROCESS process;
    PPS_CREATE_NOTIFY_INFO create_info;
    UTF8_STRING command_line_utf8;
    UTF8_STRING image_file_name_utf8;
} process_notify_context_t;

void
_ebpf_process_create_process_notify_routine_ex(
    _Inout_ PEPROCESS process, _In_ HANDLE process_id, _Inout_opt_ PPS_CREATE_NOTIFY_INFO create_info)
{
    process_notify_context_t process_notify_context = {
        .process_md = {0}, .process = process, .create_info = create_info};

    NTOS_EBPF_EXT_LOG_ENTRY();
    ntos_ebpf_extension_hook_client_t* client_context;

    if (create_info != NULL) {
        if (create_info->CommandLine != NULL) {
            NTSTATUS status =
                RtlUnicodeStringToUTF8String(&process_notify_context.command_line_utf8, create_info->CommandLine, TRUE);
            if (!NT_SUCCESS(status)) {
                goto Exit;
            }
        }
        if (create_info->ImageFileName != NULL) {
            NTSTATUS status = RtlUnicodeStringToUTF8String(
                &process_notify_context.image_file_name_utf8, create_info->ImageFileName, TRUE);
            if (!NT_SUCCESS(status)) {
                goto Exit;
            }
        }
        process_notify_context.process_md.operation = PROCESS_OPERATION_CREATE;
        process_notify_context.process_md.process_id = (uint64_t)process_id;
        process_notify_context.process_md.parent_process_id = (uint64_t)create_info->ParentProcessId;
        process_notify_context.process_md.creating_process_id = (uint64_t)create_info->CreatingThreadId.UniqueProcess;
        process_notify_context.process_md.creating_thread_id = (uint64_t)create_info->CreatingThreadId.UniqueThread;
        process_notify_context.process_md.command_start = (uint8_t*)process_notify_context.command_line_utf8.Buffer;
        process_notify_context.process_md.command_end =
            (uint8_t*)process_notify_context.command_line_utf8.Buffer + process_notify_context.command_line_utf8.Length;
    } else {
        process_notify_context.process_md.operation = PROCESS_OPERATION_DELETE;
        process_notify_context.process_md.process_id = (uint64_t)process_id;
    }

    // For each attached client call the process hook.
    ebpf_result_t result;
    client_context = ntos_ebpf_extension_hook_get_next_attached_client(_ebpf_process_hook_provider_context, NULL);
    while (client_context != NULL) {
        NTSTATUS status = 0;
        if (ntos_ebpf_extension_hook_client_enter_rundown(client_context)) {
            result = ntos_ebpf_extension_hook_invoke_program(
                client_context, &process_notify_context.process_md, (uint32_t*)&status);
            if (result != EBPF_SUCCESS) {
                NTOS_EBPF_EXT_LOG_MESSAGE(
                    NTOS_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                    NTOS_EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
                    "ntos_ebpf_extension_hook_invoke_program failed");
            }
            ntos_ebpf_extension_hook_client_leave_rundown(client_context);
        } else {
            NTOS_EBPF_EXT_LOG_MESSAGE(
                NTOS_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NTOS_EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
                "ntos_ebpf_extension_hook_client_enter_rundown failed");
        }
        // If the client returns a non-zero value, stop calling the other clients.
        if (!NT_SUCCESS(status) && create_info) {
            create_info->CreationStatus = status;
            break;
        }

        client_context =
            ntos_ebpf_extension_hook_get_next_attached_client(_ebpf_process_hook_provider_context, client_context);
    }

Exit:
    if (process_notify_context.command_line_utf8.Buffer != NULL) {
        RtlFreeUTF8String(&process_notify_context.command_line_utf8);
    }

    if (process_notify_context.image_file_name_utf8.Buffer != NULL) {
        RtlFreeUTF8String(&process_notify_context.image_file_name_utf8);
    }

    NTOS_EBPF_EXT_LOG_EXIT();
}

_Success_(return >= 0) static int32_t _ebpf_process_get_image_path(
    _In_ process_md_t* process_md, _Out_writes_bytes_(path_length) uint8_t* path, uint32_t path_length)
{
    process_notify_context_t* process_notify_context = (process_notify_context_t*)process_md;
    int32_t result = 0;
    if (process_notify_context->image_file_name_utf8.Length > path_length) {
        return -EINVAL;
    }
    if (process_notify_context->image_file_name_utf8.Buffer != NULL) {
        if (path_length >= process_notify_context->image_file_name_utf8.Length) {
            memcpy(
                path,
                process_notify_context->image_file_name_utf8.Buffer,
                process_notify_context->image_file_name_utf8.Length);
            result = process_notify_context->image_file_name_utf8.Length;
        }
    }
    return result;
}
