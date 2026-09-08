// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN
// clang-format off
#include "framework.h"
#include "..\netevent_sim\netevent_types.h"
// clang-format on
#include "catch_wrapper.hpp"
#include "cxplat_fault_injection.h"
#include "cxplat_passed_test_log.h"
#include "ebpf_netevent_hooks.h"
#include "ebpf_netevent_program_attach_type_guids.h"
#include "ebpf_structs.h"
#include "netevent_ebpf_ext_helper.h"
#include "netevent_ebpf_ext_program_info.h"
#include "utils.h"
#include "watchdog.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <ebpf_api.h>
#include <iostream>
#include <string>
#include <thread>

struct _DEVICE_OBJECT* _ebpf_ext_driver_device_object;

CATCH_REGISTER_LISTENER(_watchdog)
CATCH_REGISTER_LISTENER(cxplat_passed_test_log)

struct bpf_map* netevent_event_map;
struct bpf_map* command_map;
static uint32_t event_count = 0;
static uint32_t log_event_count = 0;
static uint32_t drop_event_count = 0;
static constexpr std::chrono::milliseconds poll_interval{5000};
static constexpr std::chrono::seconds event_timeout{90};
static constexpr std::chrono::seconds stress_test_timeout{90};
static constexpr size_t max_packet_size = 1600;

struct netevent_callback_context
{
    uint8_t expected_event_type = 0;
    bool validate_simulator_payload = false;
    uint32_t malformed_event_count = 0;
    uint32_t invalid_version_count = 0;
    uint32_t unknown_event_type_count = 0;
    uint32_t unexpected_event_type_count = 0;
    uint32_t mismatched_pktmon_event_id_count = 0;
    uint32_t invalid_payload_count = 0;
    uint64_t lost_event_count = 0;
};

static int
_drain_perf_buffer(perf_buffer* perf_buffer)
{
    auto deadline = std::chrono::steady_clock::now() + event_timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        int result = perf_buffer__poll(perf_buffer, static_cast<int>(poll_interval.count()));
        if (result <= 0) {
            return result;
        }
    }
    return -ETIMEDOUT;
}

static void
_require_no_callback_errors(const netevent_callback_context& context)
{
    REQUIRE(context.malformed_event_count == 0);
    REQUIRE(context.invalid_version_count == 0);
    REQUIRE(context.unknown_event_type_count == 0);
    REQUIRE(context.unexpected_event_type_count == 0);
    REQUIRE(context.mismatched_pktmon_event_id_count == 0);
    REQUIRE(context.invalid_payload_count == 0);
    REQUIRE(context.lost_event_count == 0);
}

typedef struct test_netevent_event_md
{
    EBPF_CONTEXT_HEADER;
    netevent_event_md_t context;
} test_netevent_event_md_t;

void
netevent_monitor_event_callback(void* ctx, int cpu, void* data, uint32_t size)
{
    UNREFERENCED_PARAMETER(cpu);
    auto& context = *static_cast<netevent_callback_context*>(ctx);

    if (data == nullptr || size < sizeof(netevent_data_header_t) + PKTMON_EVENT_HEADER_LENGTH) {
        context.malformed_event_count++;
        return;
    }

    const netevent_data_header_t* header_ptr = reinterpret_cast<const netevent_data_header_t*>(data);
    uint8_t event_type = header_ptr->type;
    event_count++;

    if (header_ptr->version != NETEVENT_PKTMON_EVENT_CURRENT_VERSION) {
        context.invalid_version_count++;
    }

    if (event_type == NETEVENT_EVENT_TYPE_PKTMON_FLOW) {
        log_event_count++;
    } else if (event_type == NETEVENT_EVENT_TYPE_PKTMON_DROP) {
        drop_event_count++;
    } else {
        context.unknown_event_type_count++;
        return;
    }

    uint8_t expected_event_type = context.expected_event_type;
    if (expected_event_type != 0 && event_type != expected_event_type) {
        context.unexpected_event_type_count++;
    }

    const netevent_message_t* message =
        reinterpret_cast<const netevent_message_t*>(static_cast<const uint8_t*>(data) + sizeof(netevent_data_header_t));
    if (message->header.EventId != event_type) {
        context.mismatched_pktmon_event_id_count++;
    }

    if (!context.validate_simulator_payload) {
        return;
    }

    if (size < sizeof(netevent_data_header_t) + sizeof(netevent_message_t)) {
        context.malformed_event_count++;
        return;
    }

    const netevent_payload_t& payload = message->payload;
    if (payload.event_id != event_type || payload.source_ip.octet1 != NETEVENT_TEST_SOURCE_IP_OCTET_1 ||
        payload.source_ip.octet2 != NETEVENT_TEST_SOURCE_IP_OCTET_2 ||
        payload.source_ip.octet3 != NETEVENT_TEST_SOURCE_IP_OCTET_3 ||
        payload.source_ip.octet4 != NETEVENT_TEST_SOURCE_IP_OCTET_4 ||
        payload.destination_ip.octet1 != NETEVENT_TEST_DESTINATION_IP_OCTET_1 ||
        payload.destination_ip.octet2 != NETEVENT_TEST_DESTINATION_IP_OCTET_2 ||
        payload.destination_ip.octet3 != NETEVENT_TEST_DESTINATION_IP_OCTET_3 ||
        payload.destination_ip.octet4 != NETEVENT_TEST_DESTINATION_IP_OCTET_4 ||
        payload.source_port != NETEVENT_TEST_SOURCE_PORT ||
        payload.destination_port != NETEVENT_TEST_DESTINATION_PORT) {
        context.invalid_payload_count++;
    }
}

void
netevent_monitor_lost_event_callback(void* ctx, int cpu, __u64 cnt)
{
    UNREFERENCED_PARAMETER(cpu);
    auto& context = *static_cast<netevent_callback_context*>(ctx);
    context.lost_event_count += cnt;
}

TEST_CASE("netevent_attach_opt_simulation", "[neteventebpfext]")
{
    // Free the BPF object will take some time to unload from the previous test
    // Once this issue is fixed, the sleep can be removed: https://github.com/microsoft/ebpf-for-windows/issues/2667
    std::this_thread::sleep_for(std::chrono::seconds(10));

    // First, load the netevent simulator driver (NPI provider).
    driver_service netevent_sim_driver;
    REQUIRE(
        netevent_sim_driver.create(L"netevent_sim", driver_service::get_driver_path("netevent_sim.sys").c_str()) ==
        true);
    REQUIRE(netevent_sim_driver.start() == true);

    // Load and start neteventebpfext extension driver.
    driver_service neteventebpfext_driver;
    REQUIRE(
        neteventebpfext_driver.create(
            L"neteventebpfext", driver_service::get_driver_path("neteventebpfext.sys").c_str()) == true);
    REQUIRE(neteventebpfext_driver.start() == true);

    // Load the NetEventMonitor native BPF program.
    struct bpf_object* object = bpf_object__open("netevent_monitor.sys");
    REQUIRE(object != nullptr);

    int res = bpf_object__load(object);
    REQUIRE(res == 0);

    // Find and attach to the netevent_monitor BPF program with attach opts.
    auto netevent_monitor = bpf_object__find_program_by_name(object, "NetEventMonitor");
    REQUIRE(netevent_monitor != nullptr);

    // Attach to the eBPF perf buffer event map.
    bpf_map* netevent_events_map = bpf_object__find_map_by_name(object, "netevent_events_map");
    REQUIRE(netevent_events_map != nullptr);
    netevent_callback_context callback_context = {};
    callback_context.expected_event_type = NETEVENT_EVENT_TYPE_PKTMON_FLOW;
    callback_context.validate_simulator_payload = true;
    auto netevent_perf_buff = perf_buffer__new(
        bpf_map__fd(netevent_events_map),
        0,
        netevent_monitor_event_callback,
        netevent_monitor_lost_event_callback,
        &callback_context,
        nullptr);
    REQUIRE(netevent_perf_buff != nullptr);

    // Test attach with no attach params - this should fail.
    ebpf_result_t result;
    bpf_link* netevent_monitor_link = nullptr;
    result = ebpf_program_attach(netevent_monitor, &EBPF_ATTACH_TYPE_NETEVENT, nullptr, 0, &netevent_monitor_link);
    REQUIRE(result != EBPF_SUCCESS);
    REQUIRE(netevent_monitor_link == nullptr);

    // Test attach with invalid size (too small) - this should fail.
    netevent_attach_opts_t attach_opts = {};
    result = ebpf_program_attach(
        netevent_monitor, &EBPF_ATTACH_TYPE_NETEVENT, &attach_opts, sizeof(attach_opts) - 1, &netevent_monitor_link);
    REQUIRE(result != EBPF_SUCCESS);

    // Test attach with invalid size (too large) - this should fail.
    result = ebpf_program_attach(
        netevent_monitor, &EBPF_ATTACH_TYPE_NETEVENT, &attach_opts, sizeof(attach_opts) - 1, &netevent_monitor_link);
    REQUIRE(result != EBPF_SUCCESS);

    // Test attach with invalid capture type - this should fail.
    attach_opts.capture_type = (netevent_capture_type_t)0;
    result = ebpf_program_attach(
        netevent_monitor, &EBPF_ATTACH_TYPE_NETEVENT, &attach_opts, sizeof(attach_opts), &netevent_monitor_link);
    REQUIRE(result != EBPF_SUCCESS);
    REQUIRE(netevent_monitor_link == nullptr);

    // Test attach with capture valid capture type
    uint32_t event_count_before = event_count;
    uint32_t log_event_count_before = log_event_count;

    attach_opts.capture_type = NeteventCapture_All;
    result = ebpf_program_attach(
        netevent_monitor, &EBPF_ATTACH_TYPE_NETEVENT, &attach_opts, sizeof(attach_opts), &netevent_monitor_link);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(netevent_monitor_link != nullptr);

    int poll_result =
        perf_buffer__poll(netevent_perf_buff, static_cast<int>(std::chrono::milliseconds(event_timeout).count()));
    REQUIRE(poll_result > 0);

    // Detach the program (link) from the attach point.
    int link_fd = bpf_link__fd(netevent_monitor_link);
    bpf_link_detach(link_fd);
    bpf_link__destroy(netevent_monitor_link);
    netevent_monitor_link = nullptr;

    REQUIRE(_drain_perf_buffer(netevent_perf_buff) >= 0);
    uint32_t event_count_after = event_count;
    uint32_t log_event_count_after = log_event_count;
    REQUIRE(log_event_count_before < log_event_count_after);
    REQUIRE((event_count_after - event_count_before) == (log_event_count_after - log_event_count_before));

    // Test reattach with different capture type
    event_count_before = event_count;
    uint32_t drop_event_count_before = drop_event_count;
    callback_context.expected_event_type = NETEVENT_EVENT_TYPE_PKTMON_DROP;
    attach_opts.capture_type = NeteventCapture_Drop;
    result = ebpf_program_attach(
        netevent_monitor, &EBPF_ATTACH_TYPE_NETEVENT, &attach_opts, sizeof(attach_opts), &netevent_monitor_link);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(netevent_monitor_link != nullptr);

    poll_result =
        perf_buffer__poll(netevent_perf_buff, static_cast<int>(std::chrono::milliseconds(event_timeout).count()));
    REQUIRE(poll_result > 0);

    // Detach the program (link) from the attach point.
    link_fd = bpf_link__fd(netevent_monitor_link);
    bpf_link_detach(link_fd);
    bpf_link__destroy(netevent_monitor_link);
    netevent_monitor_link = nullptr;

    REQUIRE(_drain_perf_buffer(netevent_perf_buff) >= 0);
    event_count_after = event_count;
    uint32_t drop_event_count_after = drop_event_count;
    REQUIRE(drop_event_count_before < drop_event_count_after);
    REQUIRE((event_count_after - event_count_before) == (drop_event_count_after - drop_event_count_before));
    _require_no_callback_errors(callback_context);

    // Close perf buffer.
    perf_buffer__free(netevent_perf_buff);

    // Free the BPF object.
    bpf_object__close(object);

    // First, stop and unload the netevent simulator driver (NPI provider).
    REQUIRE(netevent_sim_driver.stop() == true);
    REQUIRE(netevent_sim_driver.unload() == true);

    // Stop and unload the neteventebpfext extension driver (NPI client).
    REQUIRE(neteventebpfext_driver.stop() == true);
    REQUIRE(neteventebpfext_driver.unload() == true);
}

TEST_CASE("netevent_drivers_load_unload_stress", "[neteventebpfext]")
{
    // Free the BPF object will take some time to unload from the previous test
    // Once this issue is fixed, the sleep can be removed: https://github.com/microsoft/ebpf-for-windows/issues/2667
    std::this_thread::sleep_for(std::chrono::seconds(10));

    // First, load the netevent simulator driver (NPI provider).
    driver_service netevent_sim_driver;
    REQUIRE(
        netevent_sim_driver.create(L"netevent_sim", driver_service::get_driver_path("netevent_sim.sys").c_str()) ==
        true);
    REQUIRE(netevent_sim_driver.start() == true);

    // Load and start neteventebpfext extension driver.
    driver_service neteventebpfext_driver;
    REQUIRE(
        neteventebpfext_driver.create(
            L"neteventebpfext", driver_service::get_driver_path("neteventebpfext.sys").c_str()) == true);
    REQUIRE(neteventebpfext_driver.start() == true);

    // Load the NetEventMonitor native BPF program.
    struct bpf_object* object = bpf_object__open("netevent_monitor.sys");
    REQUIRE(object != nullptr);

    int res = bpf_object__load(object);
    REQUIRE(res == 0);

    // Find and attach to the netevent_monitor BPF program.
    ebpf_result_t result;
    bpf_link* netevent_monitor_link = nullptr;
    netevent_attach_opts_t attach_opts = {.capture_type = NeteventCapture_All};
    auto netevent_monitor = bpf_object__find_program_by_name(object, "NetEventMonitor");
    REQUIRE(netevent_monitor != nullptr);
    result = ebpf_program_attach(
        netevent_monitor, &EBPF_ATTACH_TYPE_NETEVENT, &attach_opts, sizeof(attach_opts), &netevent_monitor_link);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(netevent_monitor_link != nullptr);

    // Attach to the eBPF perf buffer event map.
    bpf_map* netevent_events_map = bpf_object__find_map_by_name(object, "netevent_events_map");
    REQUIRE(netevent_events_map != nullptr);
    netevent_callback_context callback_context = {};
    callback_context.expected_event_type = NETEVENT_EVENT_TYPE_PKTMON_FLOW;
    callback_context.validate_simulator_payload = true;
    auto netevent_perf_buff = perf_buffer__new(
        bpf_map__fd(netevent_events_map),
        0,
        netevent_monitor_event_callback,
        netevent_monitor_lost_event_callback,
        &callback_context,
        nullptr);
    REQUIRE(netevent_perf_buff != nullptr);

    std::cout << "\n\n********** Test netevent_sim provider load/unload while the extension is running. **********"
              << std::endl;
    auto start_time = std::chrono::high_resolution_clock::now();
    while (std::chrono::high_resolution_clock::now() - start_time < stress_test_timeout) {
        // Unload netevent_sim
        std::this_thread::sleep_for(std::chrono::seconds(5));
        REQUIRE(netevent_sim_driver.stop() == true);
        REQUIRE(netevent_sim_driver.unload() == true);

        // Sample the event count before reloading the driver,
        // after waiting for any pending events to be processed, so they don't count later.
        REQUIRE(_drain_perf_buffer(netevent_perf_buff) >= 0);
        uint32_t event_count_before = event_count;

        // Reload netevent_sim
        REQUIRE(
            netevent_sim_driver.create(L"netevent_sim", driver_service::get_driver_path("netevent_sim.sys").c_str()) ==
            true);
        REQUIRE(netevent_sim_driver.start() == true);

        // Test that the event count has increased.
        REQUIRE(
            perf_buffer__poll(netevent_perf_buff, static_cast<int>(std::chrono::milliseconds(event_timeout).count())) >
            0);
        REQUIRE(event_count > event_count_before);
    }

    std::cout << "\n\n********** Test extension load/unload while events are still being generated by the provider. "
                 "**********"
              << std::endl;
    start_time = std::chrono::high_resolution_clock::now();
    while (std::chrono::high_resolution_clock::now() - start_time < stress_test_timeout) {
        // Unload neteventebpfext
        std::this_thread::sleep_for(std::chrono::seconds(5));
        REQUIRE(neteventebpfext_driver.stop() == true);
        REQUIRE(neteventebpfext_driver.unload() == true);

        // Sample the event count before reloading the driver,
        // after waiting for any pending events to be processed, so they don't count later.
        REQUIRE(_drain_perf_buffer(netevent_perf_buff) >= 0);
        uint32_t event_count_before = event_count;

        // Reload neteventebpfext
        REQUIRE(
            neteventebpfext_driver.create(
                L"neteventebpfext", driver_service::get_driver_path("neteventebpfext.sys").c_str()) == true);
        REQUIRE(neteventebpfext_driver.start() == true);

        // Test that the event count has increased.
        REQUIRE(
            perf_buffer__poll(netevent_perf_buff, static_cast<int>(std::chrono::milliseconds(event_timeout).count())) >
            0);
        REQUIRE(event_count > event_count_before);
    }

    // Detach the program (link) from the attach point.
    int link_fd = bpf_link__fd(netevent_monitor_link);
    bpf_link_detach(link_fd);
    bpf_link__destroy(netevent_monitor_link);
    REQUIRE(_drain_perf_buffer(netevent_perf_buff) >= 0);
    _require_no_callback_errors(callback_context);

    // Close perf buffer.
    perf_buffer__free(netevent_perf_buff);

    // Free the BPF object.
    bpf_object__close(object);

    // First, stop and unload the netevent simulator driver (NPI provider).
    REQUIRE(netevent_sim_driver.stop() == true);
    REQUIRE(netevent_sim_driver.unload() == true);

    // Stop and unload the neteventebpfext extension driver (NPI client).
    REQUIRE(neteventebpfext_driver.stop() == true);
    REQUIRE(neteventebpfext_driver.unload() == true);
}

TEST_CASE("netevent_bpf_prog_run_test", "[neteventebpfext]")
{
    // The BPF object will take some time to unload from the previous test
    // TODO: Remove sleep once this issue is fixed: https://github.com/microsoft/ebpf-for-windows/issues/2667
    std::this_thread::sleep_for(std::chrono::seconds(10));

    // Load and start neteventebpfext extension driver.
    driver_service neteventebpfext_driver;
    REQUIRE(
        neteventebpfext_driver.create(
            L"neteventebpfext", driver_service::get_driver_path("neteventebpfext.sys").c_str()) == true);
    REQUIRE(neteventebpfext_driver.start() == true);

    // Load the NetEventMonitor native BPF program.
    struct bpf_object* object = bpf_object__open("netevent_monitor.sys");
    REQUIRE(object != nullptr);

    int res = bpf_object__load(object);
    REQUIRE(res == 0);

    // Find and attach to the netevent_monitor BPF program.
    ebpf_result_t result;
    bpf_link* netevent_monitor_link = nullptr;
    netevent_attach_opts_t attach_opts = {.capture_type = NeteventCapture_All};
    bpf_program* netevent_monitor = bpf_object__find_program_by_name(object, "NetEventMonitor");
    REQUIRE(netevent_monitor != nullptr);
    result = ebpf_program_attach(
        netevent_monitor, &EBPF_ATTACH_TYPE_NETEVENT, &attach_opts, sizeof(attach_opts), &netevent_monitor_link);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(netevent_monitor_link != nullptr);

    // Attach to the eBPF perf buffer event map.
    bpf_map* netevent_events_map = bpf_object__find_map_by_name(object, "netevent_events_map");
    REQUIRE(netevent_events_map != nullptr);
    netevent_callback_context callback_context = {};
    callback_context.expected_event_type = NETEVENT_EVENT_TYPE_PKTMON_DROP;
    auto netevent_perf_buff = perf_buffer__new(
        bpf_map__fd(netevent_events_map),
        0,
        netevent_monitor_event_callback,
        netevent_monitor_lost_event_callback,
        &callback_context,
        nullptr);
    REQUIRE(netevent_perf_buff != nullptr);

    // Initialize structures required for bpf_prog_test_run_opts
    bpf_test_run_opts bpf_opts = {0};
    test_netevent_event_md_t test_netevent_ctx_in = {0};
    test_netevent_event_md_t test_netevent_ctx_out = {0};
    netevent_event_md_t& netevent_ctx_in = test_netevent_ctx_in.context;
    netevent_event_md_t& netevent_ctx_out = test_netevent_ctx_out.context;
    unsigned char test_data_in[max_packet_size] = {0};
    fd_t netevent_program_fd = bpf_program__fd(netevent_monitor);
    REQUIRE(netevent_program_fd != ebpf_fd_invalid);

    // Validate well formatted pktmon data: [netevent_data_header_t (3 bytes)][PKTMON header (53 bytes)][additional
    // payload] Netevent header.
    netevent_data_header_t netevent_ext_pktmon_header = {0};
    netevent_ext_pktmon_header.version = NETEVENT_PKTMON_EVENT_CURRENT_VERSION;
    netevent_ext_pktmon_header.type = NETEVENT_EVENT_TYPE_PKTMON_DROP;

    // Pktmon header.
    unsigned char pktmon_header_data[PKTMON_EVENT_HEADER_LENGTH] = {0};
    // Set the first 4 bytes as EventId (PKTMON_EVT_STREAM_PACKET_HEADER_MINIMAL)
    *(uint32_t*)pktmon_header_data = NETEVENT_EVENT_TYPE_PKTMON_DROP;
    // Fill the rest with dummy Pktmon header data
    for (size_t i = 4; i < PKTMON_EVENT_HEADER_LENGTH; i++) {
        pktmon_header_data[i] = (unsigned char)(i % 256);
    }

    // Payload data (fake 'packet' data).
    unsigned char additional_payload[] = {'a', 'b', 'c', 'd'};
    const size_t additional_payload_size = sizeof(additional_payload);

    // Assemble the complete data: [netevent header][Pktmon header][payload]
    size_t offset = 0;
    memcpy(test_data_in + offset, &netevent_ext_pktmon_header, sizeof(netevent_data_header_t));
    offset += sizeof(netevent_data_header_t);
    memcpy(test_data_in + offset, pktmon_header_data, PKTMON_EVENT_HEADER_LENGTH);
    offset += PKTMON_EVENT_HEADER_LENGTH;
    memcpy(test_data_in + offset, additional_payload, additional_payload_size);
    offset += additional_payload_size;

    const size_t test_pktmon_data_size =
        sizeof(netevent_data_header_t) + PKTMON_EVENT_HEADER_LENGTH + additional_payload_size;
    unsigned char data_out[max_packet_size] = {0};
    uint32_t event_count_before = event_count;

    // Prepare bpf_opts.
    bpf_opts.repeat = 1;
    bpf_opts.ctx_in = &netevent_ctx_in;
    bpf_opts.ctx_size_in = sizeof(netevent_ctx_in);
    bpf_opts.ctx_out = &netevent_ctx_out;
    bpf_opts.ctx_size_out = sizeof(netevent_ctx_out);
    bpf_opts.data_in = test_data_in;
    bpf_opts.data_size_in = static_cast<uint32_t>(test_pktmon_data_size);
    bpf_opts.data_out = data_out;
    bpf_opts.data_size_out = sizeof(data_out);

    // Execute the program - expect success.
    REQUIRE(bpf_prog_test_run_opts(netevent_program_fd, &bpf_opts) == 0);

    // Validate the output params are as expected.
    REQUIRE(bpf_opts.data_size_out == test_pktmon_data_size);
    REQUIRE(memcmp(test_data_in, data_out, test_pktmon_data_size) == 0);
    REQUIRE(bpf_opts.ctx_size_out == sizeof(netevent_ctx_out));

    REQUIRE(
        perf_buffer__poll(netevent_perf_buff, static_cast<int>(std::chrono::milliseconds(event_timeout).count())) > 0);
    REQUIRE(event_count == event_count_before + 1);

    // Negative test cases.
    bpf_opts.ctx_in = NULL;
    bpf_opts.ctx_size_in = 0;

    REQUIRE(bpf_prog_test_run_opts(netevent_program_fd, &bpf_opts) != 0);

    // Context smaller than netevent_md must be rejected
    unsigned char smaller_ctx[sizeof(netevent_ctx_in) - 1];
    bpf_opts.ctx_in = &smaller_ctx;
    bpf_opts.ctx_size_in = sizeof(smaller_ctx);

    REQUIRE(bpf_prog_test_run_opts(netevent_program_fd, &bpf_opts) != 0);

    // Invalid data size should be rejected
    bpf_opts.ctx_in = &netevent_ctx_in;
    bpf_opts.ctx_size_in = sizeof(netevent_ctx_in);
    bpf_opts.data_in = test_data_in;
    // Provide less than minimal header size data
    bpf_opts.data_size_in = static_cast<uint32_t>(sizeof(netevent_data_header_t) - 1);
    REQUIRE(bpf_prog_test_run_opts(netevent_program_fd, &bpf_opts) != 0);

    // Invalid event type
    bpf_opts.ctx_in = &netevent_ctx_in;
    bpf_opts.ctx_size_in = sizeof(netevent_ctx_in);
    bpf_opts.data_in = test_data_in;
    bpf_opts.data_size_in = static_cast<uint32_t>(test_pktmon_data_size);
    // Set an invalid event type in the header
    netevent_data_header_t* event_header = reinterpret_cast<netevent_data_header_t*>(test_data_in);
    // Provide invalid event type
    event_header->type = static_cast<uint8_t>(1);
    REQUIRE(bpf_prog_test_run_opts(netevent_program_fd, &bpf_opts) != 0);

    // Detach the program (link) from the attach point.
    int link_fd = bpf_link__fd(netevent_monitor_link);
    REQUIRE(link_fd != ebpf_fd_invalid);
    REQUIRE(bpf_link_detach(link_fd) == 0);
    REQUIRE(bpf_link__destroy(netevent_monitor_link) == 0);
    REQUIRE(_drain_perf_buffer(netevent_perf_buff) >= 0);
    _require_no_callback_errors(callback_context);

    // Free the perf buffer manager
    perf_buffer__free(netevent_perf_buff);

    // Free the BPF object.
    bpf_object__close(object);

    // Stop and unload the neteventebpfext extension driver (NPI client).
    REQUIRE(neteventebpfext_driver.stop() == true);
    REQUIRE(neteventebpfext_driver.unload() == true);
}

TEST_CASE("libbpf attach type names", "[neteventebpfext][libbpf]")
{
    enum bpf_attach_type attach_type;
    const char* type_str = libbpf_bpf_attach_type_str(BPF_ATTACH_TYPE_NETEVENT);

    REQUIRE(libbpf_attach_type_by_name(type_str, &attach_type) == 0);
    REQUIRE(attach_type == BPF_ATTACH_TYPE_NETEVENT);
}