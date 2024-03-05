// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ntos_ebpf_ext.h"

#include <TraceLoggingProvider.h>
#include <winmeta.h>

TRACELOGGING_DEFINE_PROVIDER(
    ntos_ebpf_ext_tracelog_provider,
    "NtosEbpfExtProvider",
    // {d15cc421-e9e4-459b-87a6-b45b7d84e9a8}
    (0xd15cc421, 0xe9e4, 0x459b, 0x87, 0xa6, 0xb4, 0x5b, 0x7d, 0x84, 0xe9, 0xa8));

static bool _ntos_ebpf_ext_trace_initiated = false;

NTSTATUS
ntos_ebpf_ext_trace_initiate()
{
    NTSTATUS status = STATUS_SUCCESS;
    if (_ntos_ebpf_ext_trace_initiated) {
        goto Exit;
    }

    status = TraceLoggingRegister(ntos_ebpf_ext_tracelog_provider);
    if (status != STATUS_SUCCESS) {
        goto Exit;
    } else {
        _ntos_ebpf_ext_trace_initiated = true;
    }
Exit:
    return status;
}

// Prevent tail call optimization of the call to TraceLoggingUnregister to resolve verifier stop C4/DD
// "An attempt was made to unload a driver without calling EtwUnregister".
#pragma optimize("", off)
void
ntos_ebpf_ext_trace_terminate()
{
    if (_ntos_ebpf_ext_trace_initiated) {
        TraceLoggingUnregister(ntos_ebpf_ext_tracelog_provider);
        _ntos_ebpf_ext_trace_initiated = false;
    }
}
#pragma optimize("", on)

#define KEYWORD_BASE NTOS_EBPF_EXT_TRACELOG_KEYWORD_BASE
#define KEYWORD_BIND NTOS_EBPF_EXT_TRACELOG_KEYWORD_BIND
#define KEYWORD_EXT NTOS_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION
#define KEYWORD_PROCESS NTOS_EBPF_EXT_TRACELOG_KEYWORD_PROCESS
#define KEYWORD_SOCK_ADDR NTOS_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR
#define KEYWORD_SOCK_OPS NTOS_EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS
#define KEYWORD_XDP NTOS_EBPF_EXT_TRACELOG_KEYWORD_XDP

#define CASE_BASE case _NTOS_EBPF_EXT_TRACELOG_KEYWORD_BASE
#define CASE_BIND case _NTOS_EBPF_EXT_TRACELOG_KEYWORD_BIND
#define CASE_EXT case _NTOS_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION
#define CASE_PROCESS case _NTOS_EBPF_EXT_TRACELOG_KEYWORD_PROCESS
#define CASE_SOCK_ADDR case _NTOS_EBPF_EXT_TRACELOG_KEYWORD_SOCK_ADDR
#define CASE_SOCK_OPS case _NTOS_EBPF_EXT_TRACELOG_KEYWORD_SOCK_OPS
#define CASE_XDP case _NTOS_EBPF_EXT_TRACELOG_KEYWORD_XDP

#define LEVEL_LOG_ALWAYS NTOS_EBPF_EXT_TRACELOG_LEVEL_LOG_ALWAYS
#define LEVEL_CRITICAL NTOS_EBPF_EXT_TRACELOG_LEVEL_CRITICAL
#define LEVEL_ERROR NTOS_EBPF_EXT_TRACELOG_LEVEL_ERROR
#define LEVEL_WARNING NTOS_EBPF_EXT_TRACELOG_LEVEL_WARNING
#define LEVEL_INFO NTOS_EBPF_EXT_TRACELOG_LEVEL_INFO
#define LEVEL_VERBOSE NTOS_EBPF_EXT_TRACELOG_LEVEL_VERBOSE

#define CASE_LOG_ALWAYS case _NTOS_EBPF_EXT_TRACELOG_LEVEL_LOG_ALWAYS
#define CASE_CRITICAL case _NTOS_EBPF_EXT_TRACELOG_LEVEL_CRITICAL
#define CASE_LEVEL_ERROR case _NTOS_EBPF_EXT_TRACELOG_LEVEL_ERROR
#define CASE_WARNING case _NTOS_EBPF_EXT_TRACELOG_LEVEL_WARNING
#define CASE_INFO case _NTOS_EBPF_EXT_TRACELOG_LEVEL_INFO
#define CASE_VERBOSE case _NTOS_EBPF_EXT_TRACELOG_LEVEL_VERBOSE

#define NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_KEYWORD_SWITCH(api_name, status)       \
    switch (keyword) {                                                                \
    CASE_BASE:                                                                        \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_BASE, api_name, status);      \
        break;                                                                        \
    CASE_EXT:                                                                         \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_EXT, api_name, status);       \
        break;                                                                        \
    CASE_BIND:                                                                        \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_BIND, api_name, status);      \
        break;                                                                        \
    CASE_SOCK_ADDR:                                                                   \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_SOCK_ADDR, api_name, status); \
        break;                                                                        \
    CASE_SOCK_OPS:                                                                    \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_SOCK_OPS, api_name, status);  \
        break;                                                                        \
    CASE_XDP:                                                                         \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(KEYWORD_XDP, api_name, status);       \
        break;                                                                        \
    default:                                                                          \
        ebpf_assert(!"Invalid keyword");                                              \
        break;                                                                        \
    }

#pragma warning(push)
#pragma warning(disable : 6262) // Function uses 'N' bytes of stack.  Consider moving some data to heap.

__declspec(noinline) void ntos_ebpf_ext_log_ntstatus_api_failure(
    ntos_ebpf_ext_tracelog_keyword_t keyword, _In_z_ const char* api_name, NTSTATUS status)
{
    NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_KEYWORD_SWITCH(api_name, status);
}

#define NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING_KEYWORD_SWITCH(api_name, status, message, string_value)  \
    switch (keyword) {                                                                                                 \
    CASE_BASE:                                                                                                         \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(KEYWORD_BASE, api_name, status, message, string_value); \
        break;                                                                                                         \
    CASE_EXT:                                                                                                          \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(KEYWORD_EXT, api_name, status, message, string_value);  \
        break;                                                                                                         \
    CASE_BIND:                                                                                                         \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(KEYWORD_BIND, api_name, status, message, string_value); \
        break;                                                                                                         \
    CASE_SOCK_ADDR:                                                                                                    \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(                                                        \
            KEYWORD_SOCK_ADDR, api_name, status, message, string_value);                                               \
        break;                                                                                                         \
    CASE_SOCK_OPS:                                                                                                     \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(                                                        \
            KEYWORD_SOCK_OPS, api_name, status, message, string_value);                                                \
        break;                                                                                                         \
    CASE_XDP:                                                                                                          \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(KEYWORD_XDP, api_name, status, message, string_value);  \
        break;                                                                                                         \
    default:                                                                                                           \
        ebpf_assert(!"Invalid keyword");                                                                               \
        break;                                                                                                         \
    }

__declspec(noinline) void ntos_ebpf_ext_log_ntstatus_api_failure_message_string(
    ntos_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* api_name,
    NTSTATUS status,
    _In_z_ const char* message,
    _In_z_ const char* string_value)
{
    NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING_KEYWORD_SWITCH(api_name, status, message, string_value);
}

#define NTOS_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(trace_level, message)       \
    switch (keyword) {                                                       \
    CASE_BASE:                                                               \
        _NTOS_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_BASE, message);      \
        break;                                                               \
    CASE_BIND:                                                               \
        _NTOS_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_BIND, message);      \
        break;                                                               \
    CASE_EXT:                                                                \
        _NTOS_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_EXT, message);       \
        break;                                                               \
    CASE_SOCK_ADDR:                                                          \
        _NTOS_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_SOCK_ADDR, message); \
        break;                                                               \
    CASE_SOCK_OPS:                                                           \
        _NTOS_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_SOCK_OPS, message);  \
        break;                                                               \
    CASE_XDP:                                                                \
        _NTOS_EBPF_EXT_LOG_MESSAGE(trace_level, KEYWORD_XDP, message);       \
        break;                                                               \
    default:                                                                 \
        ebpf_assert(!"Invalid keyword");                                     \
        break;                                                               \
    }

__declspec(noinline) void ntos_ebpf_ext_log_message(
    ntos_ebpf_ext_tracelog_level_t trace_level, ntos_ebpf_ext_tracelog_keyword_t keyword, _In_z_ const char* message)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NTOS_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message);
        break;
    CASE_CRITICAL:
        NTOS_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_CRITICAL, message);
        break;
    CASE_LEVEL_ERROR:
        NTOS_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_ERROR, message);
        break;
    CASE_WARNING:
        NTOS_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_WARNING, message);
        break;
    CASE_INFO:
        NTOS_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_INFO, message);
        break;
    CASE_VERBOSE:
        NTOS_EBPF_EXT_LOG_MESSAGE_KEYWORD_SWITCH(LEVEL_VERBOSE, message);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NTOS_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(trace_level, message, string_value)       \
    switch (keyword) {                                                                            \
    CASE_BASE:                                                                                    \
        _NTOS_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_BASE, message, string_value);      \
        break;                                                                                    \
    CASE_BIND:                                                                                    \
        _NTOS_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_BIND, message, string_value);      \
        break;                                                                                    \
    CASE_EXT:                                                                                     \
        _NTOS_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_EXT, message, string_value);       \
        break;                                                                                    \
    CASE_SOCK_ADDR:                                                                               \
        _NTOS_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_SOCK_ADDR, message, string_value); \
        break;                                                                                    \
    CASE_SOCK_OPS:                                                                                \
        _NTOS_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_SOCK_OPS, message, string_value);  \
        break;                                                                                    \
    CASE_XDP:                                                                                     \
        _NTOS_EBPF_EXT_LOG_MESSAGE_STRING(trace_level, KEYWORD_XDP, message, string_value);       \
        break;                                                                                    \
    default:                                                                                      \
        ebpf_assert(!"Invalid keyword");                                                          \
        break;                                                                                    \
    }

__declspec(noinline) void ntos_ebpf_ext_log_message_string(
    ntos_ebpf_ext_tracelog_level_t trace_level,
    ntos_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    _In_z_ const char* string_value)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NTOS_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message, string_value);
        break;
    CASE_CRITICAL:
        NTOS_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_CRITICAL, message, string_value);
        break;
    CASE_LEVEL_ERROR:
        NTOS_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_ERROR, message, string_value);
        break;
    CASE_WARNING:
        NTOS_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_WARNING, message, string_value);
        break;
    CASE_INFO:
        NTOS_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_INFO, message, string_value);
        break;
    CASE_VERBOSE:
        NTOS_EBPF_EXT_LOG_MESSAGE_STRING_KEYWORD_SWITCH(LEVEL_VERBOSE, message, string_value);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(trace_level, message, status)       \
    switch (keyword) {                                                                        \
    CASE_BASE:                                                                                \
        _NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_BASE, message, status);      \
        break;                                                                                \
    CASE_BIND:                                                                                \
        _NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_BIND, message, status);      \
        break;                                                                                \
    CASE_EXT:                                                                                 \
        _NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_EXT, message, status);       \
        break;                                                                                \
    CASE_SOCK_ADDR:                                                                           \
        _NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_SOCK_ADDR, message, status); \
        break;                                                                                \
    CASE_SOCK_OPS:                                                                            \
        _NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_SOCK_OPS, message, status);  \
        break;                                                                                \
    CASE_XDP:                                                                                 \
        _NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS(trace_level, KEYWORD_XDP, message, status);       \
        break;                                                                                \
    default:                                                                                  \
        ebpf_assert(!"Invalid keyword");                                                      \
        break;                                                                                \
    }

__declspec(noinline) void ntos_ebpf_ext_log_message_ntstatus(
    ntos_ebpf_ext_tracelog_level_t trace_level,
    ntos_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    NTSTATUS status)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message, status);
        break;
    CASE_CRITICAL:
        NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_CRITICAL, message, status);
        break;
    CASE_LEVEL_ERROR:
        NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_ERROR, message, status);
        break;
    CASE_WARNING:
        NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_WARNING, message, status);
        break;
    CASE_INFO:
        NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_INFO, message, status);
        break;
    CASE_VERBOSE:
        NTOS_EBPF_EXT_LOG_MESSAGE_NTSTATUS_KEYWORD_SWITCH(LEVEL_VERBOSE, message, status);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NTOS_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(trace_level, message, status)       \
    switch (keyword) {                                                                      \
    CASE_BASE:                                                                              \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_BASE, message, status);      \
        break;                                                                              \
    CASE_BIND:                                                                              \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_BIND, message, status);      \
        break;                                                                              \
    CASE_EXT:                                                                               \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_EXT, message, status);       \
        break;                                                                              \
    CASE_SOCK_ADDR:                                                                         \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_SOCK_ADDR, message, status); \
        break;                                                                              \
    CASE_SOCK_OPS:                                                                          \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_SOCK_OPS, message, status);  \
        break;                                                                              \
    CASE_XDP:                                                                               \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT32(trace_level, KEYWORD_XDP, message, status);       \
        break;                                                                              \
    default:                                                                                \
        ebpf_assert(!"Invalid keyword");                                                    \
        break;                                                                              \
    }

__declspec(noinline) void ntos_ebpf_ext_log_message_uint32(
    ntos_ebpf_ext_tracelog_level_t trace_level,
    ntos_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint32_t value)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message, value);
        break;
    CASE_CRITICAL:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_CRITICAL, message, value);
        break;
    CASE_LEVEL_ERROR:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_ERROR, message, value);
        break;
    CASE_WARNING:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_WARNING, message, value);
        break;
    CASE_INFO:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_INFO, message, value);
        break;
    CASE_VERBOSE:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT32_KEYWORD_SWITCH(LEVEL_VERBOSE, message, value);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(trace_level, message, status)       \
    switch (keyword) {                                                                      \
    CASE_BASE:                                                                              \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_BASE, message, status);      \
        break;                                                                              \
    CASE_BIND:                                                                              \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_BIND, message, status);      \
        break;                                                                              \
    CASE_EXT:                                                                               \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_EXT, message, status);       \
        break;                                                                              \
    CASE_SOCK_ADDR:                                                                         \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_SOCK_ADDR, message, status); \
        break;                                                                              \
    CASE_SOCK_OPS:                                                                          \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_SOCK_OPS, message, status);  \
        break;                                                                              \
    CASE_XDP:                                                                               \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64(trace_level, KEYWORD_XDP, message, status);       \
        break;                                                                              \
    default:                                                                                \
        ebpf_assert(!"Invalid keyword");                                                    \
        break;                                                                              \
    }

__declspec(noinline) void ntos_ebpf_ext_log_message_uint64(
    ntos_ebpf_ext_tracelog_level_t trace_level,
    ntos_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message, value);
        break;
    CASE_CRITICAL:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_CRITICAL, message, value);
        break;
    CASE_LEVEL_ERROR:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_ERROR, message, value);
        break;
    CASE_WARNING:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_WARNING, message, value);
        break;
    CASE_INFO:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_INFO, message, value);
        break;
    CASE_VERBOSE:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_KEYWORD_SWITCH(LEVEL_VERBOSE, message, value);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64_KEYWORD_SWITCH(api_name, status, value1, value2)       \
    switch (keyword) {                                                                                              \
    CASE_BASE:                                                                                                      \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_BASE, api_name, status, value1, value2);      \
        break;                                                                                                      \
    CASE_EXT:                                                                                                       \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_EXT, api_name, status, value1, value2);       \
        break;                                                                                                      \
    CASE_BIND:                                                                                                      \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_BIND, api_name, status, value1, value2);      \
        break;                                                                                                      \
    CASE_SOCK_ADDR:                                                                                                 \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_SOCK_ADDR, api_name, status, value1, value2); \
        break;                                                                                                      \
    CASE_SOCK_OPS:                                                                                                  \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_SOCK_OPS, api_name, status, value1, value2);  \
        break;                                                                                                      \
    CASE_XDP:                                                                                                       \
        _NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64(KEYWORD_XDP, api_name, status, value1, value2);       \
        break;                                                                                                      \
    default:                                                                                                        \
        ebpf_assert(!"Invalid keyword");                                                                            \
        break;                                                                                                      \
    }

__declspec(noinline) void ntos_ebpf_ext_log_ntstatus_api_failure_uint64_uint64(
    ntos_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* api_name,
    NTSTATUS status,
    uint64_t value1,
    uint64_t value2)
{
    NTOS_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_UINT64_UINT64_KEYWORD_SWITCH(api_name, status, value1, value2);
}

#define NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(trace_level, message, value1, value2)       \
    switch (keyword) {                                                                                     \
    CASE_BASE:                                                                                             \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_BASE, message, value1, value2);      \
        break;                                                                                             \
    CASE_EXT:                                                                                              \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_EXT, message, value1, value2);       \
        break;                                                                                             \
    CASE_BIND:                                                                                             \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_BIND, message, value1, value2);      \
        break;                                                                                             \
    CASE_SOCK_ADDR:                                                                                        \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_SOCK_ADDR, message, value1, value2); \
        break;                                                                                             \
    CASE_SOCK_OPS:                                                                                         \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_SOCK_OPS, message, value1, value2);  \
        break;                                                                                             \
    CASE_XDP:                                                                                              \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(trace_level, KEYWORD_XDP, message, value1, value2);       \
        break;                                                                                             \
    default:                                                                                               \
        ebpf_assert(!"Invalid keyword");                                                                   \
        break;                                                                                             \
    }

__declspec(noinline) void ntos_ebpf_ext_log_message_uint64_uint64(
    ntos_ebpf_ext_tracelog_level_t trace_level,
    ntos_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value1,
    uint64_t value2)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_LOG_ALWAYS, message, value1, value2);
        break;
    CASE_CRITICAL:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_CRITICAL, message, value1, value2);
        break;
    CASE_LEVEL_ERROR:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_ERROR, message, value1, value2);
        break;
    CASE_WARNING:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_WARNING, message, value1, value2);
        break;
    CASE_INFO:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_INFO, message, value1, value2);
        break;
    CASE_VERBOSE:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_VERBOSE, message, value1, value2);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}

#define NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(trace_level, message, value1, value2, value3)  \
    switch (keyword) {                                                                                               \
    CASE_BASE:                                                                                                       \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, KEYWORD_BASE, message, value1, value2, value3); \
        break;                                                                                                       \
    CASE_EXT:                                                                                                        \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, KEYWORD_EXT, message, value1, value2, value3);  \
        break;                                                                                                       \
    CASE_BIND:                                                                                                       \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, KEYWORD_BIND, message, value1, value2, value3); \
        break;                                                                                                       \
    CASE_SOCK_ADDR:                                                                                                  \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(                                                             \
            trace_level, KEYWORD_SOCK_ADDR, message, value1, value2, value3);                                        \
        break;                                                                                                       \
    CASE_SOCK_OPS:                                                                                                   \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(                                                             \
            trace_level, KEYWORD_SOCK_OPS, message, value1, value2, value3);                                         \
        break;                                                                                                       \
    CASE_XDP:                                                                                                        \
        _NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64(trace_level, KEYWORD_XDP, message, value1, value2, value3);  \
        break;                                                                                                       \
    default:                                                                                                         \
        ebpf_assert(!"Invalid keyword");                                                                             \
        break;                                                                                                       \
    }

__declspec(noinline) void ntos_ebpf_ext_log_message_uint64_uint64_uint64(
    ntos_ebpf_ext_tracelog_level_t trace_level,
    ntos_ebpf_ext_tracelog_keyword_t keyword,
    _In_z_ const char* message,
    uint64_t value1,
    uint64_t value2,
    uint64_t value3)
{
    switch (trace_level) {
    CASE_LOG_ALWAYS:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(
            LEVEL_LOG_ALWAYS, message, value1, value2, value3);
        break;
    CASE_CRITICAL:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_CRITICAL, message, value1, value2, value3);
        break;
    CASE_LEVEL_ERROR:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_ERROR, message, value1, value2, value3);
        break;
    CASE_WARNING:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_WARNING, message, value1, value2, value3);
        break;
    CASE_INFO:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_INFO, message, value1, value2, value3);
        break;
    CASE_VERBOSE:
        NTOS_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64_UINT64_KEYWORD_SWITCH(LEVEL_VERBOSE, message, value1, value2, value3);
        break;
    default:
        ebpf_assert(!"Invalid trace level");
        break;
    }
}
#pragma warning(pop)