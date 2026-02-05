// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN
#include "catch_wrapper.hpp"
#include "cxplat_fault_injection.h"
#include "cxplat_passed_test_log.h"
#include "ebpf_ntos_hooks.h"
#include "ebpf_ntos_program_attach_type_guids.h"
#include "ebpf_structs.h"
#include "ntos_ebpf_ext_helper.h"
#include "utils.h"
#include "watchdog.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <map>
#include <stop_token>
#include <thread>
#include <wil/resource.h>

#define MAX_IMAGE_PATH_SIZE (1024)
#define MAX_COMMAND_LINE_SIZE ((64 * 1024))

struct _DEVICE_OBJECT* _ebpf_ext_driver_device_object;

CATCH_REGISTER_LISTENER(_watchdog)
CATCH_REGISTER_LISTENER(cxplat_passed_test_log)

#pragma region process

static volatile uint32_t process_event_count = 0;

// Define process_info_t to match the structure in process_monitor.c
typedef struct
{
    uint32_t process_id;
    uint32_t parent_process_id;
    uint32_t creating_process_id;
    uint32_t creating_thread_id;
    uint64_t creation_time;
    uint64_t exit_time;
    uint32_t process_exit_code;
    uint8_t operation;
} process_info_t;

static int
process_ringbuf_event_callback(void* ctx, void* data, size_t size)
{
    UNREFERENCED_PARAMETER(ctx);

    if (size != sizeof(process_info_t)) {
        std::cout << "Unexpected data size in ring buffer: " << size << " (expected " << sizeof(process_info_t) << ")"
                  << std::endl;
        return 0;
    }

    process_info_t* info = (process_info_t*)data;

    std::cout << "Ring buffer event received:" << std::endl;
    std::cout << "  Process ID: " << info->process_id << std::endl;
    std::cout << "  Parent Process ID: " << info->parent_process_id << std::endl;
    std::cout << "  Creating Process ID: " << info->creating_process_id << std::endl;
    std::cout << "  Creating Thread ID: " << info->creating_thread_id << std::endl;
    std::cout << "  Creation Time: " << info->creation_time << std::endl;
    std::cout << "  Exit Time: " << info->exit_time << std::endl;
    std::cout << "  Exit Code: " << info->process_exit_code << std::endl;
    std::cout << "  Operation: " << (info->operation == 0 ? "CREATE" : "DELETE") << std::endl;

    process_event_count++;
    return 0;
}

typedef struct test_process_client_context_t
{
    ntosebpfext_helper_base_client_context_t base;
    process_md_t process_context;
} test_process_client_context_t;

typedef struct test_process_notify_context
{
    EBPF_CONTEXT_HEADER;
    process_md_t process_md;
    void* process;
    void* create_info;
    UNICODE_STRING command_line;
    UNICODE_STRING image_file_name;
} test_process_notify_context_t;

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

    std::wstring test_command_line = std::wstring(
        reinterpret_cast<wchar_t*>(client_context.process_context.command_start),
        reinterpret_cast<wchar_t*>(client_context.process_context.command_end));

    REQUIRE(test_command_line == std::wstring(L"notepad.exe foo.txt"));

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

    std::wstring test_command_line = std::wstring(
        reinterpret_cast<wchar_t*>(client_context.process_context.command_start),
        reinterpret_cast<wchar_t*>(client_context.process_context.command_end));

    REQUIRE(test_command_line == std::wstring(L"notepad.exe foo.txt"));

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
#pragma warning(push)
#pragma warning(disable : 6387) // '_Param_(1)' could be '0':  this does not adhere to the specification for
                                // the function 'usersime_set_process_exit_status_callback'
    // Clean up callback after test.
    usersime_set_process_exit_status_callback(nullptr);
#pragma warning(pop)
}

TEST_CASE("process create and exit times", "[ntosebpfext]")
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

    const uint64_t expectedCreateTime = 123456789;
    const uint64_t expectedExitTime = 987654321;

    usersime_set_process_create_time_quadpart_callback(
        [](PEPROCESS /*process*/) -> LONGLONG { return expectedCreateTime; });
    usersime_set_process_exit_time_callback([]() -> LARGE_INTEGER {
        LARGE_INTEGER time = {0};
        time.QuadPart = expectedExitTime;
        return time;
    });

    struct
    {
        uint64_t some_value;
    } fake_eprocess = {};

    usersime_invoke_process_creation_notify_routine(
        reinterpret_cast<PEPROCESS>(&fake_eprocess), (HANDLE)1, &create_info);

    std::wstring test_command_line = std::wstring(
        reinterpret_cast<wchar_t*>(client_context.process_context.command_start),
        reinterpret_cast<wchar_t*>(client_context.process_context.command_end));

    REQUIRE(test_command_line == std::wstring(L"notepad.exe foo.txt"));

    REQUIRE(client_context.process_context.process_id == 1);
    REQUIRE((HANDLE)client_context.process_context.parent_process_id == create_info.ParentProcessId);
    REQUIRE((HANDLE)client_context.process_context.creating_process_id == create_info.CreatingThreadId.UniqueProcess);
    REQUIRE((HANDLE)client_context.process_context.creating_thread_id == create_info.CreatingThreadId.UniqueThread);
    REQUIRE(client_context.process_context.creation_time == expectedCreateTime);
    REQUIRE(client_context.process_context.exit_time == 0); // Should be 0 for creation events
    REQUIRE(create_info.CreationStatus == STATUS_ACCESS_DENIED);
    REQUIRE((int)client_context.process_context.operation == PROCESS_OPERATION_CREATE);

    // Test process termination.
    // Just verify that it doesn't crash.
    usersime_invoke_process_creation_notify_routine(reinterpret_cast<PEPROCESS>(&fake_eprocess), (HANDLE)1, nullptr);

    REQUIRE(client_context.process_context.process_id == 1);
    REQUIRE(client_context.process_context.creation_time == expectedCreateTime);
    REQUIRE(client_context.process_context.exit_time == expectedExitTime);
    REQUIRE((int)client_context.process_context.operation == PROCESS_OPERATION_DELETE);
}

TEST_CASE("libbpf attach type names", "[ntosebpfext][libbpf]")
{
    enum bpf_attach_type attach_type;
    const char* type_str = libbpf_bpf_attach_type_str(BPF_ATTACH_TYPE_PROCESS);

    REQUIRE(libbpf_attach_type_by_name(type_str, &attach_type) == 0);
    REQUIRE(attach_type == BPF_ATTACH_TYPE_PROCESS);
}

TEST_CASE("process_bpf_prog_run_test", "[ntosebpfext]")
{
    // Load and start ntosebpfext extension driver.
    driver_service ntosebpfext_driver;
    REQUIRE(
        ntosebpfext_driver.create(L"ntosebpfext", driver_service::get_driver_path("ntosebpfext.sys").c_str()) == true);
    REQUIRE(ntosebpfext_driver.start() == true);
    auto cleanup_driver = wil::scope_exit([&]() {
        ntosebpfext_driver.stop();
        ntosebpfext_driver.unload();
    });

    // Load the process monitor BPF program.
    struct bpf_object* object = bpf_object__open("process_monitor.sys");
    REQUIRE(object != nullptr);
    auto cleanup_object = wil::scope_exit([&]() {
        if (object != nullptr) {
            bpf_object__close(object);
        }
    });

    int res = bpf_object__load(object);
    REQUIRE(res == 0);

    // Find and attach to the process monitor BPF program.
    bpf_program* process_monitor = bpf_object__find_program_by_name(object, "ProcessMonitor");
    REQUIRE(process_monitor != nullptr);

    ebpf_result_t result;
    bpf_link* process_monitor_link = nullptr;
    result = ebpf_program_attach(process_monitor, &EBPF_ATTACH_TYPE_PROCESS, nullptr, 0, &process_monitor_link);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(process_monitor_link != nullptr);
    auto cleanup_link = wil::scope_exit([&]() {
        if (process_monitor_link != nullptr) {
            int link_fd = bpf_link__fd(process_monitor_link);
            if (link_fd != ebpf_fd_invalid) {
                bpf_link_detach(link_fd);
            }
            bpf_link__destroy(process_monitor_link);
        }
    });

    // Initialize structures required for bpf_prog_test_run_opts
    bpf_test_run_opts bpf_opts = {0};
    test_process_notify_context_t process_ctx_in = {0};
    test_process_notify_context_t process_ctx_out = {0};

    fd_t process_program_fd = bpf_program__fd(process_monitor);
    REQUIRE(process_program_fd != ebpf_fd_invalid);

    // Prepare test process data
    std::wstring command_line = L"notepad.exe test.txt";
    std::wstring image_path = L"C:\\Windows\\System32\\notepad.exe";

    process_ctx_in.process_md.process_id = 1234;
    process_ctx_in.process_md.parent_process_id = 4567;
    process_ctx_in.process_md.creating_process_id = 8910;
    process_ctx_in.process_md.creating_thread_id = 1112;
    process_ctx_in.process_md.operation = PROCESS_OPERATION_CREATE;
    process_ctx_in.process_md.process_exit_code = 0;
    process_ctx_in.process_md.creation_time = 123456789;
    process_ctx_in.process_md.exit_time = 0;

    // Set up UNICODE_STRING structures with only Length fields (Buffer will be NULL)
    // The actual data will be passed in data_in buffer
    process_ctx_in.command_line.Length = static_cast<USHORT>(command_line.length() * sizeof(wchar_t));
    process_ctx_in.command_line.MaximumLength = process_ctx_in.command_line.Length;
    process_ctx_in.command_line.Buffer = NULL;

    process_ctx_in.image_file_name.Length = static_cast<USHORT>(image_path.length() * sizeof(wchar_t));
    process_ctx_in.image_file_name.MaximumLength = process_ctx_in.image_file_name.Length;
    process_ctx_in.image_file_name.Buffer = NULL;

    // Manually set command_start and command_end pointers to NULL (will be set by context_create)
    process_ctx_in.process_md.command_start = NULL;
    process_ctx_in.process_md.command_end = NULL;

    // Pack both command_line and image_file_name data into a single buffer for data_in
    size_t total_data_size = static_cast<size_t>(process_ctx_in.command_line.Length) +
                             static_cast<size_t>(process_ctx_in.image_file_name.Length);
    std::vector<uint8_t> packed_data(total_data_size);

    memcpy(packed_data.data(), command_line.c_str(), process_ctx_in.command_line.Length);
    memcpy(
        packed_data.data() + process_ctx_in.command_line.Length,
        image_path.c_str(),
        process_ctx_in.image_file_name.Length);

    // Set up ring buffer consumer with auto-callback before running the test
    bpf_map* process_ringbuf_map = bpf_object__find_map_by_name(object, "process_ringbuf");
    REQUIRE(process_ringbuf_map != nullptr);
    int process_ringbuf_fd = bpf_map__fd(process_ringbuf_map);
    REQUIRE(process_ringbuf_fd != ebpf_fd_invalid);

    ebpf_ring_buffer_opts ring_opts = {.sz = sizeof(ebpf_ring_buffer_opts), .flags = EBPF_RINGBUF_FLAG_AUTO_CALLBACK};
    ring_buffer* process_ring_buffer =
        ebpf_ring_buffer__new(process_ringbuf_fd, process_ringbuf_event_callback, nullptr, &ring_opts);
    REQUIRE(process_ring_buffer != nullptr);
    auto cleanup_ring_buffer = wil::scope_exit([&]() {
        if (process_ring_buffer != nullptr) {
            ring_buffer__free(process_ring_buffer);
        }
    });

    uint32_t event_count_before = process_event_count;
    // Prepare buffer for data_out
    std::vector<uint8_t> data_out_buffer(total_data_size);

    // Prepare bpf_opts
    bpf_opts.repeat = 1;
    bpf_opts.ctx_in = &process_ctx_in;
    bpf_opts.ctx_size_in = sizeof(process_ctx_in);
    bpf_opts.ctx_out = &process_ctx_out;
    bpf_opts.ctx_size_out = sizeof(process_ctx_out);
    bpf_opts.data_in = packed_data.data();
    bpf_opts.data_size_in = static_cast<uint32_t>(total_data_size);
    bpf_opts.data_out = data_out_buffer.data();
    bpf_opts.data_size_out = static_cast<uint32_t>(total_data_size);

    // Execute the program - expect success
    REQUIRE(bpf_prog_test_run_opts(process_program_fd, &bpf_opts) == 0);

    // Validate the output context and data
    REQUIRE(bpf_opts.ctx_size_out == sizeof(process_ctx_out));
    REQUIRE(bpf_opts.data_size_out == bpf_opts.data_size_in);
    REQUIRE(process_ctx_out.process_md.process_id == process_ctx_in.process_md.process_id);
    REQUIRE(process_ctx_out.process_md.parent_process_id == process_ctx_in.process_md.parent_process_id);
    REQUIRE(process_ctx_out.process_md.operation == process_ctx_in.process_md.operation);

    // Sleep to allow auto-callback to process events
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // Validate that one event was written to the ring buffer
    REQUIRE(process_event_count > event_count_before);

    // Validate LRU_HASH maps: process_map and command_map
    bpf_map* process_map = bpf_object__find_map_by_name(object, "process_map");
    REQUIRE(process_map != nullptr);
    int process_map_fd = bpf_map__fd(process_map);
    REQUIRE(process_map_fd != ebpf_fd_invalid);

    bpf_map* command_map = bpf_object__find_map_by_name(object, "command_map");
    REQUIRE(command_map != nullptr);
    int command_map_fd = bpf_map__fd(command_map);
    REQUIRE(command_map_fd != ebpf_fd_invalid);

    // Lookup the process_id in process_map to verify image path was stored
    uint32_t lookup_key = (uint32_t)process_ctx_in.process_md.process_id;
    std::vector<wchar_t> image_path_from_map(MAX_IMAGE_PATH_SIZE / sizeof(wchar_t));
    int result_process = bpf_map_lookup_elem(process_map_fd, &lookup_key, image_path_from_map.data());
    REQUIRE(result_process == 0);
    REQUIRE(wcscmp(image_path_from_map.data(), image_path.c_str()) == 0);

    // Lookup the process_id in command_map to verify command line was stored
    std::vector<wchar_t> command_line_from_map(MAX_COMMAND_LINE_SIZE / sizeof(wchar_t));
    int result_command = bpf_map_lookup_elem(command_map_fd, &lookup_key, command_line_from_map.data());
    REQUIRE(result_command == 0);
    REQUIRE(wcscmp(command_line_from_map.data(), command_line.c_str()) == 0);

    // Test negative cases

    // Context smaller than process_notify_context_t must be rejected
    unsigned char smaller_ctx[sizeof(process_ctx_in) - 1];
    bpf_opts.ctx_in = &smaller_ctx;
    bpf_opts.ctx_size_in = sizeof(smaller_ctx);
    REQUIRE(bpf_prog_test_run_opts(process_program_fd, &bpf_opts) != 0);

    // NULL context should be rejected
    bpf_opts.ctx_in = nullptr;
    bpf_opts.ctx_size_in = 0;
    REQUIRE(bpf_prog_test_run_opts(process_program_fd, &bpf_opts) != 0);
}

#pragma endregion process