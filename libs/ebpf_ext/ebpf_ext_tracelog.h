// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include <TraceLoggingProvider.h>
#include <winmeta.h>

TRACELOGGING_DECLARE_PROVIDER(ebpf_ext_tracelog_provider);

NTSTATUS
ebpf_ext_trace_initiate();

void
ebpf_ext_trace_terminate();

#define EBPF_EXT_TRACELOG_EVENT_SUCCESS "NtosEbpfExtSuccess"
#define EBPF_EXT_TRACELOG_EVENT_RETURN "NtosEbpfExtReturn"
#define EBPF_EXT_TRACELOG_EVENT_GENERIC_ERROR "NtosEbpfExtGenericError"
#define EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE "NtosEbpfExtGenericMessage"
#define EBPF_EXT_TRACELOG_EVENT_API_ERROR "NtosEbpfExtApiError"

#define EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT 0x1
#define EBPF_EXT_TRACELOG_KEYWORD_BASE 0x2
#define EBPF_EXT_TRACELOG_KEYWORD_EXTENSION 0x4
#define EBPF_EXT_TRACELOG_KEYWORD_XDP 0x8
#define EBPF_EXT_TRACELOG_KEYWORD_BIND 0x10
#define EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR 0x20
#define EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS 0x40
#define EBPF_EXT_TRACELOG_KEYWORD_PROCESS 0x80
#define EBPF_EXT_TRACELOG_KEYWORD_NETEVENT 0x100

#define EBPF_EXT_TRACELOG_LEVEL_LOG_ALWAYS WINEVENT_LEVEL_LOG_ALWAYS
#define EBPF_EXT_TRACELOG_LEVEL_CRITICAL WINEVENT_LEVEL_CRITICAL
#define EBPF_EXT_TRACELOG_LEVEL_ERROR WINEVENT_LEVEL_ERROR
#define EBPF_EXT_TRACELOG_LEVEL_WARNING WINEVENT_LEVEL_WARNING
#define EBPF_EXT_TRACELOG_LEVEL_INFO WINEVENT_LEVEL_INFO
#define EBPF_EXT_TRACELOG_LEVEL_VERBOSE WINEVENT_LEVEL_VERBOSE

typedef enum _ebpf_ext_tracelog_keyword
{
    _EBPF_EXT_TRACELOG_KEYWORD_BASE,
    _EBPF_EXT_TRACELOG_KEYWORD_BIND,
    _EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
    _EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR,
    _EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS,
    _EBPF_EXT_TRACELOG_KEYWORD_XDP,
    _EBPF_EXT_TRACELOG_KEYWORD_PROCESS,
    _EBPF_EXT_TRACELOG_KEYWORD_NETEVENT,
} ebpf_ext_tracelog_keyword_t;

typedef enum _ebpf_ext_tracelog_level
{
    _EBPF_EXT_TRACELOG_LEVEL_LOG_ALWAYS,
    _EBPF_EXT_TRACELOG_LEVEL_CRITICAL,
    _EBPF_EXT_TRACELOG_LEVEL_ERROR,
    _EBPF_EXT_TRACELOG_LEVEL_WARNING,
    _EBPF_EXT_TRACELOG_LEVEL_INFO,
    _EBPF_EXT_TRACELOG_LEVEL_VERBOSE
} ebpf_ext_tracelog_level_t;

#define EBPF_EXT_LOG_FUNCTION_SUCCESS()                                                                     \
    if (TraceLoggingProviderEnabled(                                                                        \
            ebpf_ext_tracelog_provider, EBPF_EXT_TRACELOG_LEVEL_VERBOSE, EBPF_EXT_TRACELOG_KEYWORD_BASE)) { \
        TraceLoggingWrite(                                                                                  \
            ebpf_ext_tracelog_provider,                                                                     \
            EBPF_EXT_TRACELOG_EVENT_SUCCESS,                                                                \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                                                      \
            TraceLoggingKeyword(EBPF_EXT_TRACELOG_KEYWORD_BASE),                                            \
            TraceLoggingString(__FUNCTION__ " returned success", "Message"));                               \
    }

#define EBPF_EXT_LOG_FUNCTION_ERROR(result)                                                                 \
    if (TraceLoggingProviderEnabled(                                                                        \
            ebpf_ext_tracelog_provider, EBPF_EXT_TRACELOG_LEVEL_VERBOSE, EBPF_EXT_TRACELOG_KEYWORD_BASE)) { \
        TraceLoggingWrite(                                                                                  \
            ebpf_ext_tracelog_provider,                                                                     \
            EBPF_EXT_TRACELOG_EVENT_GENERIC_ERROR,                                                          \
            TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                                                        \
            TraceLoggingKeyword(EBPF_EXT_TRACELOG_KEYWORD_BASE),                                            \
            TraceLoggingString(__FUNCTION__ " returned error", "ErrorMessage"),                             \
            TraceLoggingLong(result, "Error"));                                                             \
    }

#define EBPF_EXT_LOG_ENTRY()                                                    \
    if (TraceLoggingProviderEnabled(                                            \
            ebpf_ext_tracelog_provider,                                         \
            EBPF_EXT_TRACELOG_LEVEL_VERBOSE,                                    \
            EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT)) {                   \
        TraceLoggingWrite(                                                      \
            ebpf_ext_tracelog_provider,                                         \
            EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                            \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                          \
            TraceLoggingKeyword(EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT), \
            TraceLoggingOpcode(WINEVENT_OPCODE_START),                          \
            TraceLoggingString(__FUNCTION__, "Enter"));                         \
    }

#define EBPF_EXT_LOG_EXIT()                                                     \
    if (TraceLoggingProviderEnabled(                                            \
            ebpf_ext_tracelog_provider,                                         \
            EBPF_EXT_TRACELOG_LEVEL_VERBOSE,                                    \
            EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT)) {                   \
        TraceLoggingWrite(                                                      \
            ebpf_ext_tracelog_provider,                                         \
            EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                            \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),                          \
            TraceLoggingKeyword(EBPF_EXT_TRACELOG_KEYWORD_FUNCTION_ENTRY_EXIT), \
            TraceLoggingOpcode(WINEVENT_OPCODE_STOP),                           \
            TraceLoggingString(__FUNCTION__, "Exit"));                          \
    }

#define _EBPF_EXT_LOG_NTSTATUS_API_FAILURE(keyword, api, status) \
    TraceLoggingWrite(                                           \
        ebpf_ext_tracelog_provider,                              \
        EBPF_EXT_TRACELOG_EVENT_API_ERROR,                       \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                 \
        TraceLoggingKeyword((keyword)),                          \
        TraceLoggingString(api, "api"),                          \
        TraceLoggingNTStatus(status));
void
ebpf_ext_log_ntstatus_api_failure(ebpf_ext_tracelog_keyword_t keyword, _In_z_ const char* api_name, NTSTATUS status);
#define EBPF_EXT_LOG_NTSTATUS_API_FAILURE(keyword, api, status)                \
    if (TraceLoggingProviderEnabled(ebpf_ext_tracelog_provider, 0, keyword)) { \
        ebpf_ext_log_ntstatus_api_failure(_##keyword##, api, status);          \
    }

#define _EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(keyword, api, status, message, value) \
    TraceLoggingWrite(                                                                          \
        ebpf_ext_tracelog_provider,                                                             \
        EBPF_EXT_TRACELOG_EVENT_API_ERROR,                                                      \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                                                \
        TraceLoggingKeyword((keyword)),                                                         \
        TraceLoggingString(api, "api"),                                                         \
        TraceLoggingNTStatus(status),                                                           \
        TraceLoggingString(message, "Message"),                                                 \
        TraceLoggingString((value), (#value)));
void
ebpf_ext_log_ntstatus_api_failure_message_string(
    ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* api_name,
    NTSTATUS status,
    _In_z_ const char* message,
    _In_z_ const char* string_value);
#define EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(keyword, api, status, message, string_value)       \
    if (TraceLoggingProviderEnabled(ebpf_ext_tracelog_provider, 0, keyword)) {                              \
        ebpf_ext_log_ntstatus_api_failure_message_string(_##keyword##, api, status, message, string_value); \
    }

#define _EBPF_EXT_LOG_MESSAGE(trace_level, keyword, message) \
    TraceLoggingWrite(                                       \
        ebpf_ext_tracelog_provider,                          \
        EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,             \
        TraceLoggingLevel(trace_level),                      \
        TraceLoggingKeyword((keyword)),                      \
        TraceLoggingString(message, "Message"));
void
ebpf_ext_log_message(
    ebpf_ext_tracelog_level_t trace_level, ebpf_ext_tracelog_keyword_t keyword, _In_z_ const char* message);
#define EBPF_EXT_LOG_MESSAGE(trace_level, keyword, message)                              \
    if (TraceLoggingProviderEnabled(ebpf_ext_tracelog_provider, trace_level, keyword)) { \
        ebpf_ext_log_message(_##trace_level##, _##keyword##, message);                   \
    }

#define _EBPF_EXT_LOG_MESSAGE_STRING(trace_level, keyword, message, value) \
    TraceLoggingWrite(                                                     \
        ebpf_ext_tracelog_provider,                                        \
        EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                           \
        TraceLoggingLevel(trace_level),                                    \
        TraceLoggingKeyword((keyword)),                                    \
        TraceLoggingString(message, "Message"),                            \
        TraceLoggingString((value), (#value)));
void
ebpf_ext_log_message_string(
    ebpf_ext_tracelog_level_t trace_level,
    ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    _In_z_ const char* string_value);
#define EBPF_EXT_LOG_MESSAGE_STRING(trace_level, keyword, message, value)                \
    if (TraceLoggingProviderEnabled(ebpf_ext_tracelog_provider, trace_level, keyword)) { \
        ebpf_ext_log_message_string(_##trace_level##, _##keyword##, message, value);     \
    }

#define _EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, keyword, message, status) \
    TraceLoggingWrite(                                                        \
        ebpf_ext_tracelog_provider,                                           \
        EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                              \
        TraceLoggingLevel(trace_level),                                       \
        TraceLoggingKeyword((keyword)),                                       \
        TraceLoggingString(message, "Message"),                               \
        TraceLoggingNTStatus(status));
void
ebpf_ext_log_message_ntstatus(
    ebpf_ext_tracelog_level_t trace_level,
    ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    NTSTATUS status);
#define EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, keyword, message, status)             \
    if (TraceLoggingProviderEnabled(ebpf_ext_tracelog_provider, trace_level, keyword)) { \
        ebpf_ext_log_message_ntstatus(_##trace_level##, _##keyword##, message, status);  \
    }

#define _EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, keyword, message, value) \
    TraceLoggingWrite(                                                     \
        ebpf_ext_tracelog_provider,                                        \
        EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                           \
        TraceLoggingLevel(trace_level),                                    \
        TraceLoggingKeyword((keyword)),                                    \
        TraceLoggingString(message, "Message"),                            \
        TraceLoggingUInt32((value), (#value)));
void
ebpf_ext_log_message_uint32(
    ebpf_ext_tracelog_level_t trace_level,
    ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint32_t value);
#define EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, keyword, message, value)                \
    if (TraceLoggingProviderEnabled(ebpf_ext_tracelog_provider, trace_level, keyword)) { \
        ebpf_ext_log_message_uint32(_##trace_level##, _##keyword##, message, value);     \
    }

#define _EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, keyword, message, value) \
    TraceLoggingWrite(                                                     \
        ebpf_ext_tracelog_provider,                                        \
        EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                           \
        TraceLoggingLevel(trace_level),                                    \
        TraceLoggingKeyword((keyword)),                                    \
        TraceLoggingString(message, "Message"),                            \
        TraceLoggingUInt64((value), (#value)));
void
ebpf_ext_log_message_uint64(
    ebpf_ext_tracelog_level_t trace_level,
    ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value);
#define EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, keyword, message, value)                \
    if (TraceLoggingProviderEnabled(ebpf_ext_tracelog_provider, trace_level, keyword)) { \
        ebpf_ext_log_message_uint64(_##trace_level##, _##keyword##, message, value);     \
    }

#define _EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(keyword, api, status, value1, value2) \
    TraceLoggingWrite(                                                                         \
        ebpf_ext_tracelog_provider,                                                            \
        EBPF_EXT_TRACELOG_EVENT_API_ERROR,                                                     \
        TraceLoggingLevel(WINEVENT_LEVEL_ERROR),                                               \
        TraceLoggingKeyword(keyword),                                                          \
        TraceLoggingString(api, "api"),                                                        \
        TraceLoggingNTStatus(status),                                                          \
        TraceLoggingUInt64((value1), (#value1)),                                               \
        TraceLoggingUInt64((value2), (#value2)));
void
ebpf_ext_log_ntstatus_api_failure_uint64_uint64(
    ebpf_ext_tracelog_keyword_t keyword, _In_z_ const char* api, NTSTATUS status, uint64_t value1, uint64_t value2);
#define EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(keyword, api, status, value1, value2)       \
    if (TraceLoggingProviderEnabled(ebpf_ext_tracelog_provider, 0, keyword)) {                      \
        ebpf_ext_log_ntstatus_api_failure_uint64_uint64(_##keyword##, api, status, value1, value2); \
    }

#define _EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, keyword, message, value1, value2) \
    TraceLoggingWrite(                                                                     \
        ebpf_ext_tracelog_provider,                                                        \
        EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                                           \
        TraceLoggingLevel(trace_level),                                                    \
        TraceLoggingKeyword((keyword)),                                                    \
        TraceLoggingString(message, "Message"),                                            \
        TraceLoggingUInt64((value1), (#value1)),                                           \
        TraceLoggingUInt64((value2), (#value2)));
void
ebpf_ext_log_message_uint64_uint64(
    ebpf_ext_tracelog_level_t trace_level,
    ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value1,
    uint64_t value2);
#define EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, keyword, message, value1, value2)            \
    if (TraceLoggingProviderEnabled(ebpf_ext_tracelog_provider, trace_level, keyword)) {             \
        ebpf_ext_log_message_uint64_uint64(_##trace_level##, _##keyword##, message, value1, value2); \
    }

#define _EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, keyword, message, value1, value2, value3) \
    TraceLoggingWrite(                                                                                    \
        ebpf_ext_tracelog_provider,                                                                       \
        EBPF_EXT_TRACELOG_EVENT_GENERIC_MESSAGE,                                                          \
        TraceLoggingLevel(trace_level),                                                                   \
        TraceLoggingKeyword((keyword)),                                                                   \
        TraceLoggingString(message, "Message"),                                                           \
        TraceLoggingUInt64((value1), (#value1)),                                                          \
        TraceLoggingUInt64((value2), (#value2)),                                                          \
        TraceLoggingUInt64((value3), (#value3)));
void
ebpf_ext_log_message_uint64_uint64_uint64(
    ebpf_ext_tracelog_level_t trace_level,
    ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value1,
    uint64_t value2,
    uint64_t value3);
#define EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, keyword, message, value1, value2, value3)            \
    if (TraceLoggingProviderEnabled(ebpf_ext_tracelog_provider, trace_level, keyword)) {                            \
        ebpf_ext_log_message_uint64_uint64_uint64(_##trace_level##, _##keyword##, message, value1, value2, value3); \
    }
//
// Macros built on top of the above primary trace macros.
//

#define EBPF_EXT_RETURN_RESULT(status)                 \
    do {                                               \
        ebpf_result_t local_result = (status);         \
        if (local_result == EBPF_SUCCESS) {            \
            EBPF_EXT_LOG_FUNCTION_SUCCESS();           \
        } else {                                       \
            EBPF_EXT_LOG_FUNCTION_ERROR(local_result); \
        }                                              \
        return local_result;                           \
    } while (false);

#define EBPF_EXT_RETURN_NTSTATUS(status)               \
    do {                                               \
        NTSTATUS local_result = (status);              \
        if (NT_SUCCESS(local_result)) {                \
            EBPF_EXT_LOG_FUNCTION_SUCCESS();           \
        } else {                                       \
            EBPF_EXT_LOG_FUNCTION_ERROR(local_result); \
        }                                              \
        return local_result;                           \
    } while (false);

#define EBPF_EXT_RETURN_POINTER(type, pointer)                   \
    do {                                                         \
        type local_result = (type)(pointer);                     \
        TraceLoggingWrite(                                       \
            ebpf_ext_tracelog_provider,                          \
            EBPF_EXT_TRACELOG_EVENT_RETURN,                      \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),           \
            TraceLoggingKeyword(EBPF_EXT_TRACELOG_KEYWORD_BASE), \
            TraceLoggingString(__FUNCTION__ " returned"),        \
            TraceLoggingPointer(local_result, #pointer));        \
        return local_result;                                     \
    } while (false);

#define EBPF_EXT_RETURN_BOOL(flag)                               \
    do {                                                         \
        bool local_result = (flag);                              \
        TraceLoggingWrite(                                       \
            ebpf_ext_tracelog_provider,                          \
            EBPF_EXT_TRACELOG_EVENT_RETURN,                      \
            TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),           \
            TraceLoggingKeyword(EBPF_EXT_TRACELOG_KEYWORD_BASE), \
            TraceLoggingString(__FUNCTION__ " returned"),        \
            TraceLoggingBool(!!local_result, #flag));            \
        return local_result;                                     \
    } while (false);

#define EBPF_EXT_BAIL_ON_ERROR_RESULT(result)          \
    do {                                               \
        ebpf_result_t local_result = (result);         \
        if (local_result != EBPF_SUCCESS) {            \
            EBPF_EXT_LOG_FUNCTION_ERROR(local_result); \
            goto Exit;                                 \
        }                                              \
    } while (false);

#define EBPF_EXT_BAIL_ON_ERROR_STATUS(status)          \
    do {                                               \
        NTSTATUS local_status = (status);              \
        if (!NT_SUCCESS(local_status)) {               \
            EBPF_EXT_LOG_FUNCTION_ERROR(local_status); \
            goto Exit;                                 \
        }                                              \
    } while (false);

#define EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(keyword, ptr, ptr_name, result)                                     \
    do {                                                                                                          \
        if ((ptr) == NULL) {                                                                                      \
            EBPF_EXT_LOG_MESSAGE(                                                                                 \
                EBPF_EXT_TRACELOG_LEVEL_ERROR, ##keyword##, "Failed to allocate " #ptr_name " in " __FUNCTION__); \
            (result) = EBPF_NO_MEMORY;                                                                            \
            goto Exit;                                                                                            \
        }                                                                                                         \
    } while (false);

#define EBPF_EXT_BAIL_ON_ALLOC_FAILURE_STATUS(keyword, ptr, ptr_name, status)                                     \
    do {                                                                                                          \
        if ((ptr) == NULL) {                                                                                      \
            EBPF_EXT_LOG_MESSAGE(                                                                                 \
                EBPF_EXT_TRACELOG_LEVEL_ERROR, ##keyword##, "Failed to allocate " #ptr_name " in " __FUNCTION__); \
            (status) = STATUS_INSUFFICIENT_RESOURCES;                                                             \
            goto Exit;                                                                                            \
        }                                                                                                         \
    } while (false);

#define EBPF_EXT_BAIL_ON_API_FAILURE_STATUS(keyword, api, status)            \
    do {                                                                     \
        NTSTATUS local_status = (status);                                    \
        if (!NT_SUCCESS(local_status)) {                                     \
            EBPF_EXT_LOG_NTSTATUS_API_FAILURE(##keyword##, (api), (status)); \
            goto Exit;                                                       \
        }                                                                    \
    } while (false);