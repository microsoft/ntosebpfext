// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN
#include "catch_wrapper.hpp"
#include "cxplat_fault_injection.h"
#include "cxplat_passed_test_log.h"
#include "ebpf_ntos_hooks.h"
#include "ntos_ebpf_ext_helper.h"
#include "watchdog.h"

#include <map>
#include <stop_token>
#include <thread>

struct _DEVICE_OBJECT* _ebpf_ext_driver_device_object;

CATCH_REGISTER_LISTENER(_watchdog)
CATCH_REGISTER_LISTENER(cxplat_passed_test_log)

#pragma region process

typedef struct test_process_client_context_t
{
    ntosebpfext_helper_base_client_context_t base;
    process_md_t process_context;
} test_process_client_context_t;

_Must_inspect_result_ ebpf_result_t
ntosebpfext_unit_invoke_process_program(
    _In_ const void* client_process_context, _In_ const void* context, _Out_ uint32_t* result)
{
    process_md_t* process_context = (process_md_t*)context;
    test_process_client_context_t* client_context = (test_process_client_context_t*)client_process_context;

    client_context->process_context = *process_context;
    *result = STATUS_ACCESS_DENIED;
    return EBPF_SUCCESS;
}

TEST_CASE("process_invoke", "[ntosebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_process_client_context_t client_context = {};

    ntosebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)ntosebpfext_unit_invoke_process_program,
        (ntosebpfext_helper_base_client_context_t*)&client_context);

    // Test process creation.
    std::wstring process_name = L"notepad.exe";
    std::wstring command_line = L"notepad.exe foo.txt";
    UNICODE_STRING process_name_unicode = {};
    UNICODE_STRING command_line_unicode = {};

    PS_CREATE_NOTIFY_INFO create_info = {};
    create_info.CommandLine = &command_line_unicode;
    create_info.ImageFileName = &process_name_unicode;
    create_info.ParentProcessId = (HANDLE)4;
    create_info.CreatingThreadId.UniqueProcess = (HANDLE)5;
    create_info.CreatingThreadId.UniqueThread = (HANDLE)6;
    create_info.CreationStatus = STATUS_SUCCESS;

    RtlInitUnicodeString(&process_name_unicode, process_name.c_str());
    RtlInitUnicodeString(&command_line_unicode, command_line.c_str());

    struct
    {
        uint64_t some_value;
    } fake_eprocess = {};

    usersime_invoke_process_creation_notify_routine(
        reinterpret_cast<PEPROCESS>(&fake_eprocess), (HANDLE)1, &create_info);

    std::string test_command_line = std::string(
        reinterpret_cast<char*>(client_context.process_context.command_start),
        reinterpret_cast<char*>(client_context.process_context.command_end));

    REQUIRE(test_command_line == std::string("notepad.exe foo.txt"));

    REQUIRE(client_context.process_context.process_id == 1);
    REQUIRE((HANDLE)client_context.process_context.parent_process_id == create_info.ParentProcessId);
    REQUIRE((HANDLE)client_context.process_context.creating_process_id == create_info.CreatingThreadId.UniqueProcess);
    REQUIRE((HANDLE)client_context.process_context.creating_thread_id == create_info.CreatingThreadId.UniqueThread);
    REQUIRE(client_context.process_context.process_exit_code == 0); // Should be 0 for creation events
    REQUIRE(create_info.CreationStatus == STATUS_ACCESS_DENIED);
    REQUIRE((int)client_context.process_context.operation == PROCESS_OPERATION_CREATE);

    // Test process termination.
    // Just verify that it doesn't crash.
    usersime_invoke_process_creation_notify_routine(reinterpret_cast<PEPROCESS>(&fake_eprocess), (HANDLE)1, nullptr);

    REQUIRE(client_context.process_context.process_id == 1);
    // The exit code should be -1 in tests, becaus we haven't set up a callback to specify the exit code (see the
    // process exit codes test below for that).
    REQUIRE(client_context.process_context.process_exit_code == -1);
    REQUIRE((int)client_context.process_context.operation == PROCESS_OPERATION_DELETE);
}

TEST_CASE("process exit codes", "[ntosebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_process_client_context_t client_context = {};

    ntosebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)ntosebpfext_unit_invoke_process_program,
        (ntosebpfext_helper_base_client_context_t*)&client_context);

    // Test process creation.
    std::wstring process_name = L"notepad.exe";
    std::wstring command_line = L"notepad.exe foo.txt";
    UNICODE_STRING process_name_unicode = {};
    UNICODE_STRING command_line_unicode = {};

    PS_CREATE_NOTIFY_INFO create_info = {};
    create_info.CommandLine = &command_line_unicode;
    create_info.ImageFileName = &process_name_unicode;
    create_info.ParentProcessId = (HANDLE)4;
    create_info.CreatingThreadId.UniqueProcess = (HANDLE)5;
    create_info.CreatingThreadId.UniqueThread = (HANDLE)6;
    create_info.CreationStatus = STATUS_SUCCESS;

    RtlInitUnicodeString(&process_name_unicode, process_name.c_str());
    RtlInitUnicodeString(&command_line_unicode, command_line.c_str());

    struct
    {
        uint64_t some_value;
    } fake_eprocess = {};

    usersime_invoke_process_creation_notify_routine(
        reinterpret_cast<PEPROCESS>(&fake_eprocess), (HANDLE)1, &create_info);

    const int expectedExitCode = 118;

    usersime_set_process_exit_status_callback([](PEPROCESS process) -> NTSTATUS { return expectedExitCode; });

    std::string test_command_line = std::string(
        reinterpret_cast<char*>(client_context.process_context.command_start),
        reinterpret_cast<char*>(client_context.process_context.command_end));

    REQUIRE(test_command_line == std::string("notepad.exe foo.txt"));

    REQUIRE(client_context.process_context.process_id == 1);
    REQUIRE((HANDLE)client_context.process_context.parent_process_id == create_info.ParentProcessId);
    REQUIRE((HANDLE)client_context.process_context.creating_process_id == create_info.CreatingThreadId.UniqueProcess);
    REQUIRE((HANDLE)client_context.process_context.creating_thread_id == create_info.CreatingThreadId.UniqueThread);
    REQUIRE(client_context.process_context.process_exit_code == 0); // Should be 0 for creation events
    REQUIRE(create_info.CreationStatus == STATUS_ACCESS_DENIED);
    REQUIRE((int)client_context.process_context.operation == PROCESS_OPERATION_CREATE);

    // Test process termination.
    // Just verify that it doesn't crash.
    usersime_invoke_process_creation_notify_routine(reinterpret_cast<PEPROCESS>(&fake_eprocess), (HANDLE)1, nullptr);

    REQUIRE(client_context.process_context.process_id == 1);
    REQUIRE(client_context.process_context.process_exit_code == expectedExitCode);
    REQUIRE((int)client_context.process_context.operation == PROCESS_OPERATION_DELETE);
}

#pragma endregion process