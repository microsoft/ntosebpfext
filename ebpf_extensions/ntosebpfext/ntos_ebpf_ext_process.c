// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief This file implements the process program type hook on eBPF for Windows.
 */

#include "ebpf_ntos_hooks.h"
#include "ntos_ebpf_ext_process.h"
#include "ntos_ebpf_ext_program_info.h"
#include "shared_context.h"

#include <errno.h>
#include <limits.h>

// Maximum number of bytes for inline account name/domain buffers on the stack.
#define ACCOUNT_STRING_INLINE_BYTES 80

// Define the pool tag for this extension
ULONG EBPF_EXTENSION_POOL_TAG = EBPF_NTOS_EXTENSION_POOL_TAG;

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

_Success_(return >= 0) static int32_t _ebpf_process_get_account_name(
    _In_ process_md_t* process_md, _Out_writes_bytes_(name_length) uint8_t* name, uint32_t name_length);

_Success_(return >= 0) static int32_t _ebpf_process_get_account_domain(
    _In_ process_md_t* process_md, _Out_writes_bytes_(domain_length) uint8_t* domain, uint32_t domain_length);

static const void* _ebpf_process_helper_functions[] = {
    (void*)&_ebpf_process_get_image_path,
    (void*)&_ebpf_process_get_account_name,
    (void*)&_ebpf_process_get_account_domain,
};

static ebpf_helper_function_addresses_t _ebpf_process_helper_function_address_table = {
    .header = {EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION, EBPF_HELPER_FUNCTION_ADDRESSES_CURRENT_VERSION_SIZE},
    .helper_function_count = EBPF_COUNT_OF(_ebpf_process_helper_functions),
    .helper_function_address = (uint64_t*)_ebpf_process_helper_functions,
};

//
// Process Program Information NPI Provider.
//
static ebpf_program_data_t _ebpf_process_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_process_program_info,
    .program_type_specific_helper_function_addresses = &_ebpf_process_helper_function_address_table,
    .context_create = _ebpf_process_context_create,
    .context_destroy = _ebpf_process_context_destroy,
    .required_irql = PASSIVE_LEVEL,
};

static ebpf_extension_data_t _ebpf_process_program_info_provider_data = {
    .header = {EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_process_program_data)},
    .data = &_ebpf_process_program_data};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_process_program_info_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ebpf_extension_program_info_provider_t* _ebpf_process_program_info_provider_context = NULL;

//
// Process Hook NPI Provider.
//
ebpf_attach_provider_data_t _ntos_ebpf_process_hook_provider_data = {
    .header = {EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION, EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE},
    .supported_program_type = EBPF_PROGRAM_TYPE_PROCESS_GUID,
    .bpf_attach_type = (bpf_attach_type_t)BPF_ATTACH_TYPE_PROCESS,
};

NPI_MODULEID DECLSPEC_SELECTANY _ebpf_process_hook_provider_moduleid = {sizeof(NPI_MODULEID), MIT_GUID, {0}};

static ebpf_extension_hook_provider_t* _ebpf_process_hook_provider_context = NULL;

EX_PUSH_LOCK _ebpf_process_hook_provider_lock;
bool _ebpf_process_hook_provider_registered = FALSE;
uint64_t _ebpf_process_hook_provider_registration_count = 0;

//
// Client attach/detach handler routines.
//

static ebpf_result_t
_ntos_ebpf_extension_process_on_client_attach(
    _In_ const ebpf_extension_hook_client_t* attaching_client,
    _In_ const ebpf_extension_hook_provider_t* provider_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    bool push_lock_acquired = false;

    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(attaching_client);
    UNREFERENCED_PARAMETER(provider_context);

    ExAcquirePushLockExclusive(&_ebpf_process_hook_provider_lock);

    push_lock_acquired = true;

    if (!_ebpf_process_hook_provider_registered) {
        // Register the process create notify routine.
        NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(_ebpf_process_create_process_notify_routine_ex, FALSE);
        if (!NT_SUCCESS(status)) {
            EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
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

    EBPF_EXT_RETURN_RESULT(result);
}

static void
_ntos_ebpf_extension_process_on_client_detach(_In_ const ebpf_extension_hook_client_t* detaching_client)
{
    ebpf_result_t result = EBPF_SUCCESS;

    EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(detaching_client);

    // Unregister the process create notify routine.
    ExAcquirePushLockExclusive(&_ebpf_process_hook_provider_lock);

    _ebpf_process_hook_provider_registration_count--;

    if (_ebpf_process_hook_provider_registered && _ebpf_process_hook_provider_registration_count == 0) {
        NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(_ebpf_process_create_process_notify_routine_ex, TRUE);
        if (!NT_SUCCESS(status)) {
            EBPF_EXT_LOG_MESSAGE_NTSTATUS(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
                "PsSetCreateProcessNotifyRoutineEx failed",
                status);
            result = EBPF_OPERATION_NOT_SUPPORTED;
        }
        _ebpf_process_hook_provider_registered = FALSE;
    }

    ExReleasePushLockExclusive(&_ebpf_process_hook_provider_lock);

    EBPF_EXT_LOG_EXIT();
}

//
// NMR Registration Helper Routines.
//

void
ebpf_ext_unregister_ntos()
{
    if (_ebpf_process_hook_provider_context) {
        ebpf_extension_hook_provider_unregister(_ebpf_process_hook_provider_context);
        _ebpf_process_hook_provider_context = NULL;
    }
    if (_ebpf_process_program_info_provider_context) {
        ebpf_extension_program_info_provider_unregister(_ebpf_process_program_info_provider_context);
        _ebpf_process_program_info_provider_context = NULL;
    }
}

NTSTATUS
ebpf_ext_register_ntos()
{
    NTSTATUS status = STATUS_SUCCESS;

    EBPF_EXT_LOG_ENTRY();

    const ebpf_extension_program_info_provider_parameters_t program_info_provider_parameters = {
        &_ebpf_process_program_info_provider_moduleid, &_ebpf_process_program_data};
    const ebpf_extension_hook_provider_parameters_t hook_provider_parameters = {
        &_ebpf_process_hook_provider_moduleid, &_ntos_ebpf_process_hook_provider_data};

    // Set the program type as the provider module id.
    _ebpf_process_program_info_provider_moduleid.Guid = EBPF_PROGRAM_TYPE_PROCESS;
    _ebpf_process_hook_provider_moduleid.Guid = EBPF_ATTACH_TYPE_PROCESS;
    status = ebpf_extension_program_info_provider_register(
        &program_info_provider_parameters, &_ebpf_process_program_info_provider_context);
    if (!NT_SUCCESS(status)) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
            "ebpf_extension_program_info_provider_register",
            status);
        goto Exit;
    }

    status = ebpf_extension_hook_provider_register(
        &hook_provider_parameters,
        _ntos_ebpf_extension_process_on_client_attach,
        _ntos_ebpf_extension_process_on_client_detach,
        NULL,
        &_ebpf_process_hook_provider_context);
    if (status != EBPF_SUCCESS) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
            "ebpf_extension_hook_provider_register",
            status);
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        ebpf_ext_unregister_ntos();
    }
    EBPF_EXT_RETURN_NTSTATUS(status);
}

typedef struct _process_notify_context
{
    EBPF_CONTEXT_HEADER;
    process_md_t process_md;
    PEPROCESS process;
    PPS_CREATE_NOTIFY_INFO create_info;
    UNICODE_STRING command_line;
    UNICODE_STRING image_file_name;
    UNICODE_STRING account_name;
    UNICODE_STRING account_domain;
    BOOLEAN account_lookup_done;
} process_notify_context_t;

// Wrapper used only by context_create/context_destroy (bpf_prog_test_run path).
// Tracks the initial account buffers so context_destroy can free them if
// _ebpf_process_resolve_account replaced them with heap-allocated buffers.
typedef struct _process_test_context
{
    process_notify_context_t base;
    PWSTR account_name_initial_buffer;
    PWSTR account_domain_initial_buffer;
} process_test_context_t;

// Deep-copy a UNICODE_STRING from a packed data buffer, advancing the data pointer.
static ebpf_result_t
_deep_copy_unicode_string_from_data(
    _Out_ UNICODE_STRING* dest, _In_ const UNICODE_STRING* src_descriptor, _Inout_ const uint8_t** data_ptr)
{
    if (src_descriptor->Length == 0) {
        RtlInitUnicodeString(dest, NULL);
        return EBPF_SUCCESS;
    }
    dest->Buffer =
        (PWSTR)ExAllocatePoolUninitialized(NonPagedPoolNx, src_descriptor->MaximumLength, EBPF_EXTENSION_POOL_TAG);
    if (dest->Buffer == NULL) {
        return EBPF_NO_MEMORY;
    }
#pragma warning(push)
#pragma warning(disable : 6386) // Length <= MaximumLength validated by caller.
    memcpy(dest->Buffer, *data_ptr, src_descriptor->Length);
#pragma warning(pop)
    dest->Length = src_descriptor->Length;
    dest->MaximumLength = src_descriptor->MaximumLength;
    *data_ptr += src_descriptor->Length;
    return EBPF_SUCCESS;
}

// Copy a UNICODE_STRING's content into a caller-supplied byte buffer.
static int32_t
_copy_unicode_string_to_buffer(
    _In_ const UNICODE_STRING* source, _Out_writes_bytes_(dest_length) uint8_t* dest, uint32_t dest_length)
{
    if (source->Length > dest_length) {
        return -EINVAL;
    }
    if (source->Buffer != NULL && source->Length > 0) {
        memcpy(dest, source->Buffer, source->Length);
        return (int32_t)source->Length;
    }
    return 0;
}

static ebpf_result_t
_ebpf_process_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    EBPF_EXT_LOG_ENTRY();
    ebpf_result_t result;
    process_test_context_t* test_context = NULL;
    process_notify_context_t* process_context = NULL;
    process_notify_context_t* input_context = NULL;
    const uint8_t* data_ptr = data_in;

    *context = NULL;
    input_context = (process_notify_context_t*)context_in;

    if (context_in == NULL || context_size_in < sizeof(process_notify_context_t)) {
        EBPF_EXT_LOG_MESSAGE(EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_PROCESS, "Context is required");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    if (data_in == NULL ||
        data_size_in < ((size_t)input_context->command_line.Length + (size_t)input_context->image_file_name.Length +
                        (size_t)input_context->account_name.Length + (size_t)input_context->account_domain.Length)) {
        EBPF_EXT_LOG_MESSAGE(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
            "Insufficient data for variable-length fields");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Validate that Length does not exceed MaximumLength for each UNICODE_STRING.
    if (input_context->command_line.Length > input_context->command_line.MaximumLength ||
        input_context->image_file_name.Length > input_context->image_file_name.MaximumLength ||
        input_context->account_name.Length > input_context->account_name.MaximumLength ||
        input_context->account_domain.Length > input_context->account_domain.MaximumLength) {
        EBPF_EXT_LOG_MESSAGE(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
            "UNICODE_STRING Length exceeds MaximumLength");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    test_context = (process_test_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, sizeof(process_test_context_t), EBPF_EXTENSION_POOL_TAG);
    EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(EBPF_EXT_TRACELOG_KEYWORD_PROCESS, test_context, "process_context", result);

    memset(test_context, 0, sizeof(process_test_context_t));
    process_context = &test_context->base;

    // Copy the context from the caller.
    memcpy(process_context, context_in, sizeof(process_notify_context_t));

    // Sanitize pointer fields that should not come from bpf_prog_test_run input.
    // These are kernel pointers that must be NULL when creating context from user mode.
    process_context->process = NULL;
    process_context->create_info = NULL;

    // Parse data_in buffer: [command_line][image_file_name][account_name][account_domain]
    // The lengths are specified in the UNICODE_STRING structures from the context.

    result =
        _deep_copy_unicode_string_from_data(&process_context->command_line, &input_context->command_line, &data_ptr);
    if (result != EBPF_SUCCESS) {
        EBPF_EXT_LOG_MESSAGE(
            EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_PROCESS, "Failed to allocate command_line buffer");
        goto Exit;
    }

    result = _deep_copy_unicode_string_from_data(
        &process_context->image_file_name, &input_context->image_file_name, &data_ptr);
    if (result != EBPF_SUCCESS) {
        EBPF_EXT_LOG_MESSAGE(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
            "Failed to allocate image_file_name buffer");
        goto Exit;
    }

    result =
        _deep_copy_unicode_string_from_data(&process_context->account_name, &input_context->account_name, &data_ptr);
    if (result != EBPF_SUCCESS) {
        EBPF_EXT_LOG_MESSAGE(
            EBPF_EXT_TRACELOG_LEVEL_ERROR, EBPF_EXT_TRACELOG_KEYWORD_PROCESS, "Failed to allocate account_name buffer");
        goto Exit;
    }

    result = _deep_copy_unicode_string_from_data(
        &process_context->account_domain, &input_context->account_domain, &data_ptr);
    if (result != EBPF_SUCCESS) {
        EBPF_EXT_LOG_MESSAGE(
            EBPF_EXT_TRACELOG_LEVEL_ERROR,
            EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
            "Failed to allocate account_domain buffer");
        goto Exit;
    }

    // Save initial buffer pointers so context_destroy can free them if
    // _ebpf_process_resolve_account replaced them with heap-allocated buffers.
    test_context->account_name_initial_buffer = process_context->account_name.Buffer;
    test_context->account_domain_initial_buffer = process_context->account_domain.Buffer;

    // Set command_start and command_end to point to the copied command_line buffer
    process_context->process_md.command_start = (uint8_t*)process_context->command_line.Buffer;
    process_context->process_md.command_end =
        (uint8_t*)process_context->command_line.Buffer + process_context->command_line.Length;

    *context = &process_context->process_md;
    test_context = NULL;
    result = EBPF_SUCCESS;

Exit:
    if (test_context) {
        process_context = &test_context->base;
        if (process_context->command_line.Buffer != NULL) {
            ExFreePool(process_context->command_line.Buffer);
        }
        if (process_context->image_file_name.Buffer != NULL) {
            ExFreePool(process_context->image_file_name.Buffer);
        }
        if (process_context->account_name.Buffer != NULL) {
            ExFreePool(process_context->account_name.Buffer);
        }
        if (process_context->account_domain.Buffer != NULL) {
            ExFreePool(process_context->account_domain.Buffer);
        }
        ExFreePool(test_context);
        test_context = NULL;
    }
    EBPF_EXT_RETURN_RESULT(result);
}

static void
_ebpf_process_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    EBPF_EXT_LOG_ENTRY();

    process_md_t* process_md = (process_md_t*)context;
    process_notify_context_t* process_context = NULL;
    process_notify_context_t* process_context_out = (process_notify_context_t*)context_out;
    size_t total_data_size = 0;

    if (!process_md) {
        goto Exit;
    }

    // Get the containing process_notify_context_t structure from the process_md pointer.
    process_context = CONTAINING_RECORD(process_md, process_notify_context_t, process_md);

    if (context_out != NULL && *context_size_out >= sizeof(process_notify_context_t)) {
        // Copy the context to the caller.
        memcpy(process_context_out, process_context, sizeof(process_notify_context_t));

        // Zero out buffers.
        process_context_out->command_line.Buffer = 0;
        process_context_out->image_file_name.Buffer = 0;
        process_context_out->account_name.Buffer = 0;
        process_context_out->account_domain.Buffer = 0;
        process_context_out->process_md.command_start = 0;
        process_context_out->process_md.command_end = 0;
        *context_size_out = sizeof(process_notify_context_t);
    } else {
        *context_size_out = 0;
    }

    // Pack variable-length fields into data_out, mirroring data_in structure
    total_data_size = (size_t)process_context->command_line.Length + (size_t)process_context->image_file_name.Length +
                      (size_t)process_context->account_name.Length + (size_t)process_context->account_domain.Length;
    if (data_out != NULL && *data_size_out >= total_data_size) {
        uint8_t* data_ptr = data_out;

        // Copy command_line buffer
        if (process_context->command_line.Length > 0 && process_context->command_line.Buffer != NULL) {
            memcpy(data_ptr, process_context->command_line.Buffer, process_context->command_line.Length);
            data_ptr += process_context->command_line.Length;
        }

        // Copy image_file_name buffer
        if (process_context->image_file_name.Length > 0 && process_context->image_file_name.Buffer != NULL) {
            memcpy(data_ptr, process_context->image_file_name.Buffer, process_context->image_file_name.Length);
            data_ptr += process_context->image_file_name.Length;
        }

        // Copy account_name buffer
        if (process_context->account_name.Length > 0 && process_context->account_name.Buffer != NULL) {
            memcpy(data_ptr, process_context->account_name.Buffer, process_context->account_name.Length);
            data_ptr += process_context->account_name.Length;
        }

        // Copy account_domain buffer
        if (process_context->account_domain.Length > 0 && process_context->account_domain.Buffer != NULL) {
            memcpy(data_ptr, process_context->account_domain.Buffer, process_context->account_domain.Length);
            data_ptr += process_context->account_domain.Length;
        }

        *data_size_out = total_data_size;
    } else {
        *data_size_out = 0;
    }

    // Free the deep-copied buffers.
    // Recover the test wrapper to check if _ebpf_process_resolve_account replaced
    // account buffers with heap-allocated ones.
    if (process_context->command_line.Buffer != NULL) {
        ExFreePool(process_context->command_line.Buffer);
    }
    if (process_context->image_file_name.Buffer != NULL) {
        ExFreePool(process_context->image_file_name.Buffer);
    }
    {
        process_test_context_t* test_context = CONTAINING_RECORD(process_context, process_test_context_t, base);
        if (test_context->account_name_initial_buffer != NULL &&
            test_context->account_name_initial_buffer != process_context->account_name.Buffer) {
            ExFreePool(test_context->account_name_initial_buffer);
        }
        if (test_context->account_domain_initial_buffer != NULL &&
            test_context->account_domain_initial_buffer != process_context->account_domain.Buffer) {
            ExFreePool(test_context->account_domain_initial_buffer);
        }
    }
    if (process_context->account_name.Buffer != NULL) {
        ExFreePool(process_context->account_name.Buffer);
    }
    if (process_context->account_domain.Buffer != NULL) {
        ExFreePool(process_context->account_domain.Buffer);
    }
    ExFreePool(CONTAINING_RECORD(process_context, process_test_context_t, base));

Exit:
    EBPF_EXT_LOG_EXIT();
}

void
_ebpf_process_create_process_notify_routine_ex(
    _Inout_ PEPROCESS process, _In_ HANDLE process_id, _Inout_opt_ PPS_CREATE_NOTIFY_INFO create_info)
{
    WCHAR account_name_stack_buffer[ACCOUNT_STRING_INLINE_BYTES / sizeof(WCHAR)] = {0};
    WCHAR account_domain_stack_buffer[ACCOUNT_STRING_INLINE_BYTES / sizeof(WCHAR)] = {0};

    process_notify_context_t process_notify_context = {
        .process_md = {0},
        .process = process,
        .create_info = create_info,
        .command_line = {0},
        .image_file_name = {0},
        .account_name = {0},
        .account_domain = {0},
        .account_lookup_done = FALSE};

    // Point account UNICODE_STRINGs at stack-allocated inline buffers.
    process_notify_context.account_name.Buffer = account_name_stack_buffer;
    process_notify_context.account_name.MaximumLength = ACCOUNT_STRING_INLINE_BYTES;
    process_notify_context.account_domain.Buffer = account_domain_stack_buffer;
    process_notify_context.account_domain.MaximumLength = ACCOUNT_STRING_INLINE_BYTES;

    EBPF_EXT_LOG_ENTRY();
    ebpf_extension_hook_client_t* client_context;

    process_notify_context.process_md.process_id = (uint64_t)process_id;
    process_notify_context.process_md.creation_time = PsGetProcessCreateTimeQuadPart(process);

    if (create_info != NULL) {
        if (create_info->CommandLine != NULL) {
            process_notify_context.command_line = *create_info->CommandLine;
        }
        if (create_info->ImageFileName != NULL) {
            process_notify_context.image_file_name = *create_info->ImageFileName;
        }
        process_notify_context.process_md.operation = PROCESS_OPERATION_CREATE;
        process_notify_context.process_md.parent_process_id = (uint64_t)create_info->ParentProcessId;
        process_notify_context.process_md.creating_process_id = (uint64_t)create_info->CreatingThreadId.UniqueProcess;
        process_notify_context.process_md.creating_thread_id = (uint64_t)create_info->CreatingThreadId.UniqueThread;
        process_notify_context.process_md.command_start = (uint8_t*)process_notify_context.command_line.Buffer;
        process_notify_context.process_md.command_end =
            (uint8_t*)process_notify_context.command_line.Buffer + process_notify_context.command_line.Length;

        // Get the primary token SID for the new process.
        {
            PACCESS_TOKEN token = PsReferencePrimaryToken(process);
            if (token != NULL) {
                PTOKEN_USER token_user = NULL;
                NTSTATUS sid_status = SeQueryInformationToken(token, TokenUser, (PVOID*)&token_user);
                if (NT_SUCCESS(sid_status) && token_user != NULL) {
                    if (RtlValidSid(token_user->User.Sid)) {
                        ULONG sid_length = RtlLengthSid(token_user->User.Sid);
                        if (sid_length <= TOKEN_SID_MAX_SIZE) {
                            NTSTATUS copy_status = RtlCopySid(
                                TOKEN_SID_MAX_SIZE,
                                (PSID)process_notify_context.process_md.token_sid,
                                token_user->User.Sid);
                            if (NT_SUCCESS(copy_status)) {
                                process_notify_context.process_md.token_sid_size = sid_length;
                            }
                        }
                    }
                    ExFreePool(token_user);
                }
                PsDereferencePrimaryToken(token);
            }
        }

    } else {
        process_notify_context.process_md.operation = PROCESS_OPERATION_DELETE;
        process_notify_context.process_md.exit_time = PsGetProcessExitTime().QuadPart;
        process_notify_context.process_md.process_exit_code = PsGetProcessExitStatus(process);
    }

    // For each attached client call the process hook.
    ebpf_result_t result;
    client_context = ebpf_extension_hook_get_next_attached_client(_ebpf_process_hook_provider_context, NULL);
    while (client_context != NULL) {
        NTSTATUS status = 0;
        if (ebpf_extension_hook_client_enter_rundown(client_context)) {
            result = ebpf_extension_hook_invoke_program(
                client_context, &process_notify_context.process_md, (uint32_t*)&status);
            if (result != EBPF_SUCCESS) {
                EBPF_EXT_LOG_MESSAGE(
                    EBPF_EXT_TRACELOG_LEVEL_ERROR,
                    EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
                    "ebpf_extension_hook_invoke_program failed");
            }
            ebpf_extension_hook_client_leave_rundown(client_context);
        } else {
            EBPF_EXT_LOG_MESSAGE(
                EBPF_EXT_TRACELOG_LEVEL_ERROR,
                EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
                "ebpf_extension_hook_client_enter_rundown failed");
        }
        // If the client returns a non-zero value, stop calling the other clients.
        if (!NT_SUCCESS(status) && create_info) {
            create_info->CreationStatus = status;
            break;
        }

        client_context =
            ebpf_extension_hook_get_next_attached_client(_ebpf_process_hook_provider_context, client_context);
    }

    if (process_notify_context.account_name.Buffer != NULL &&
        process_notify_context.account_name.Buffer != account_name_stack_buffer) {
        ExFreePool(process_notify_context.account_name.Buffer);
    }
    if (process_notify_context.account_domain.Buffer != NULL &&
        process_notify_context.account_domain.Buffer != account_domain_stack_buffer) {
        ExFreePool(process_notify_context.account_domain.Buffer);
    }
    EBPF_EXT_LOG_EXIT();
}

_Success_(return >= 0) static int32_t _ebpf_process_get_image_path(
    _In_ process_md_t* process_md, _Out_writes_bytes_(path_length) uint8_t* path, uint32_t path_length)
{
    process_notify_context_t* process_notify_context =
        CONTAINING_RECORD(process_md, process_notify_context_t, process_md);
    return _copy_unicode_string_to_buffer(&process_notify_context->image_file_name, path, path_length);
}

// Lazily resolve the account name and domain from the process token SID.
// Called on first invocation of either account helper; results are cached.
static NTSTATUS
_ebpf_process_resolve_account(_Inout_ process_notify_context_t* process_notify_context)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN name_heap_allocated = FALSE;
    BOOLEAN domain_heap_allocated = FALSE;
    ULONG name_size = 0;
    ULONG domain_size = 0;
    SID_NAME_USE name_use;
    PSID sid = (PSID)process_notify_context->process_md.token_sid;

    if (process_notify_context->account_lookup_done) {
        // On a previous failure the cleanup code set Buffer to NULL.
        return (process_notify_context->account_name.Buffer != NULL &&
                process_notify_context->account_domain.Buffer != NULL)
                   ? STATUS_SUCCESS
                   : STATUS_UNSUCCESSFUL;
    }

    // The SID was already captured by the notify routine into process_md.token_sid.
    if (process_notify_context->process_md.token_sid_size == 0) {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    if (!RtlValidSid(sid)) {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    name_size = process_notify_context->account_name.MaximumLength;
    domain_size = process_notify_context->account_domain.MaximumLength;

    // Try the lookup optimistically with the existing (stack) buffers.
    status = SecLookupAccountSid(
        sid,
        &name_size,
        &process_notify_context->account_name,
        &domain_size,
        &process_notify_context->account_domain,
        &name_use);

    if (status == STATUS_BUFFER_TOO_SMALL) {
        // Guard against USHORT truncation when casting ULONG sizes.
        if (name_size > USHRT_MAX || domain_size > USHRT_MAX) {
            status = STATUS_BUFFER_OVERFLOW;
            goto Exit;
        }

        // Stack buffers too small — heap-allocate with the returned sizes and retry.
        if (name_size > process_notify_context->account_name.MaximumLength) {
            PWSTR new_buf = (PWSTR)ExAllocatePoolUninitialized(NonPagedPoolNx, name_size, EBPF_EXTENSION_POOL_TAG);
            if (new_buf != NULL) {
                process_notify_context->account_name.Buffer = new_buf;
                process_notify_context->account_name.MaximumLength = (USHORT)name_size;
                name_heap_allocated = TRUE;
            } else {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }
        }

        if (domain_size > process_notify_context->account_domain.MaximumLength) {
            PWSTR new_buf = (PWSTR)ExAllocatePoolUninitialized(NonPagedPoolNx, domain_size, EBPF_EXTENSION_POOL_TAG);
            if (new_buf != NULL) {
                process_notify_context->account_domain.Buffer = new_buf;
                process_notify_context->account_domain.MaximumLength = (USHORT)domain_size;
                domain_heap_allocated = TRUE;
            } else {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }
        }

        status = SecLookupAccountSid(
            sid,
            &name_size,
            &process_notify_context->account_name,
            &domain_size,
            &process_notify_context->account_domain,
            &name_use);
    }

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

Exit:
    // Cache the result unconditionally (success or failure) to avoid redundant
    // kernel API calls if multiple eBPF programs invoke account helpers.
    process_notify_context->account_lookup_done = TRUE;
    if (!NT_SUCCESS(status)) {
        // Clear account results on failure.
        if (name_heap_allocated) {
            ExFreePool(process_notify_context->account_name.Buffer);
        }
        process_notify_context->account_name.Buffer = NULL;
        process_notify_context->account_name.Length = 0;
        process_notify_context->account_name.MaximumLength = 0;
        if (domain_heap_allocated) {
            ExFreePool(process_notify_context->account_domain.Buffer);
        }
        process_notify_context->account_domain.Buffer = NULL;
        process_notify_context->account_domain.Length = 0;
        process_notify_context->account_domain.MaximumLength = 0;
    }

    return status;
}

_Success_(return >= 0) static int32_t _ebpf_process_get_account_name(
    _In_ process_md_t* process_md, _Out_writes_bytes_(name_length) uint8_t* name, uint32_t name_length)
{
    process_notify_context_t* process_notify_context =
        CONTAINING_RECORD(process_md, process_notify_context_t, process_md);
    NTSTATUS status = _ebpf_process_resolve_account(process_notify_context);
    if (!NT_SUCCESS(status)) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_WARNING,
            EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
            "Failed to resolve account name",
            status);
        return -ENOENT;
    }
    return _copy_unicode_string_to_buffer(&process_notify_context->account_name, name, name_length);
}

_Success_(return >= 0) static int32_t _ebpf_process_get_account_domain(
    _In_ process_md_t* process_md, _Out_writes_bytes_(domain_length) uint8_t* domain, uint32_t domain_length)
{
    process_notify_context_t* process_notify_context =
        CONTAINING_RECORD(process_md, process_notify_context_t, process_md);
    NTSTATUS status = _ebpf_process_resolve_account(process_notify_context);
    if (!NT_SUCCESS(status)) {
        EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            EBPF_EXT_TRACELOG_LEVEL_WARNING,
            EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
            "Failed to resolve account domain",
            status);
        return -ENOENT;
    }
    return _copy_unicode_string_to_buffer(&process_notify_context->account_domain, domain, domain_length);
}
