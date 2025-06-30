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
#include "netevent_ebpf_ext_helper.h"
#include "netevent_ebpf_ext_program_info.h"
#include "utils.h"
#include "watchdog.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ebpf_api.h>
#include <iostream>
#include <string>
#include <thread>

struct _DEVICE_OBJECT* _ebpf_ext_driver_device_object;

CATCH_REGISTER_LISTENER(_watchdog)
CATCH_REGISTER_LISTENER(cxplat_passed_test_log)

#define MAX_EVENTS_COUNT 1000
#define NETEVENT_EVENT_TEST_TIMEOUT_SEC 90
#define NETEVENT_EVENT_STRESS_TEST_TIMEOUT_SEC 90
#define MAX_PACKET_SIZE 1600

struct bpf_map* netevent_event_map;
struct bpf_map* command_map;
static volatile uint32_t event_count = 0;
static volatile uint32_t log_event_count = 0;
static volatile uint32_t drop_event_count = 0;

typedef struct test_netevent_event_md
{
    EBPF_CONTEXT_HEADER;
    netevent_event_md_t context;
} test_netevent_event_md_t;

void
_dump_event(uint8_t event_type, const char* event_descr, void* data, size_t size)
{
    netevent_data_header_t* header_ptr = reinterpret_cast<netevent_data_header_t*>(data);
    if ((event_type == NETEVENT_EVENT_TYPE_PKTMON_DROP || event_type == NETEVENT_EVENT_TYPE_PKTMON_FLOW)) {
        // Cast the event and print its details
        netevent_message_t* test_message =
            reinterpret_cast<netevent_message_t*>((static_cast<char*>(data) + sizeof(netevent_data_header_t)));
        netevent_payload_t* test_payload = static_cast<netevent_payload_t*>(&test_message->payload);
        std::cout << "\rNetwork event [" << test_payload->event_counter << "]: {"
                  << "src: " << (int)test_payload->source_ip.octet1 << "." << (int)test_payload->source_ip.octet2 << "."
                  << (int)test_payload->source_ip.octet3 << "." << (int)test_payload->source_ip.octet4 << ":"
                  << test_payload->source_port << ", "
                  << "dst: " << (int)test_payload->destination_ip.octet1 << "."
                  << (int)test_payload->destination_ip.octet2 << "." << (int)test_payload->destination_ip.octet3 << "."
                  << (int)test_payload->destination_ip.octet4 << ":" << test_payload->destination_port;
        std::cout << "}" << std::flush;
    } else {
        // Simply dump the event data as hex bytes.
        std::cout << std::endl
                  << "\r>>> " << event_descr << " - type[" << (int)event_type << "], " << size << " bytes: { ";
        for (size_t i = 0; i < size; ++i) {
            std::cout << std::setw(2) << std::setfill('0') << std::hex
                      << static_cast<int>(reinterpret_cast<const std::byte*>(data)[i]) << " ";
        }
        std::cout << "}" << std::flush;
        std::cout << std::dec; // Reset to decimal.
    }
}

int
netevent_monitor_event_callback(void* ctx, void* data, size_t size)
{
    // Parameter checks.
    UNREFERENCED_PARAMETER(ctx);
    if (data == nullptr || size == 0 || size < sizeof(netevent_data_header_t)) {
        std::cout << "empty event fired" << std::flush;
        return 0;
    }

    // Check if this event is actually a netevent event (i.e. first byte is NETEVENT_EVENT_TYPE_PKTMON_DROP).
    netevent_data_header_t* header_ptr = reinterpret_cast<netevent_data_header_t*>(data);
    uint8_t event_type = header_ptr->type;
    event_count++;
    std::cout << "event type fired" << (int)event_type << std::flush;
    if (event_type == NETEVENT_EVENT_TYPE_PKTMON_FLOW) {
        log_event_count++;
    } else if (event_type == NETEVENT_EVENT_TYPE_PKTMON_DROP) {
        drop_event_count++;
    } else {
        return 0;
    }
    _dump_event(event_type, "netevent_event", data, size);

    return 0;
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

    // Attach to the eBPF ring buffer event map.
    bpf_map* netevent_events_map = bpf_object__find_map_by_name(object, "netevent_events_map");
    REQUIRE(netevent_events_map != nullptr);
    auto ring = ring_buffer__new(bpf_map__fd(netevent_events_map), netevent_monitor_event_callback, nullptr, nullptr);
    REQUIRE(ring != nullptr);

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
    uint32_t drop_event_count_before = drop_event_count;

    attach_opts.capture_type = NeteventCapture_All;
    result = ebpf_program_attach(
        netevent_monitor, &EBPF_ATTACH_TYPE_NETEVENT, &attach_opts, sizeof(attach_opts), &netevent_monitor_link);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(netevent_monitor_link != nullptr);
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // Detach the program (link) from the attach point.
    int link_fd = bpf_link__fd(netevent_monitor_link);
    bpf_link_detach(link_fd);
    bpf_link__destroy(netevent_monitor_link);

    // Test that only expected event counts have increased
    std::this_thread::sleep_for(std::chrono::seconds(5));
    REQUIRE(log_event_count_before < log_event_count);
    REQUIRE((event_count - event_count_before) == (log_event_count - log_event_count_before));

    // Test reattach with different capture type
    event_count_before = event_count;
    attach_opts.capture_type = NeteventCapture_Drop;
    result = ebpf_program_attach(
        netevent_monitor, &EBPF_ATTACH_TYPE_NETEVENT, &attach_opts, sizeof(attach_opts), &netevent_monitor_link);
    REQUIRE(result == EBPF_SUCCESS);
    REQUIRE(netevent_monitor_link != nullptr);
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // Detach the program (link) from the attach point.
    link_fd = bpf_link__fd(netevent_monitor_link);
    bpf_link_detach(link_fd);
    bpf_link__destroy(netevent_monitor_link);

    // Test that only expected event counts have increased
    std::this_thread::sleep_for(std::chrono::seconds(5));
    REQUIRE(drop_event_count_before < drop_event_count);
    REQUIRE((event_count - event_count_before) == (drop_event_count - drop_event_count_before));

    // Close ring buffer.
    ring_buffer__free(ring);

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

    // Attach to the eBPF ring buffer event map.
    bpf_map* netevent_events_map = bpf_object__find_map_by_name(object, "netevent_events_map");
    REQUIRE(netevent_events_map != nullptr);
    auto ring = ring_buffer__new(bpf_map__fd(netevent_events_map), netevent_monitor_event_callback, nullptr, nullptr);
    REQUIRE(ring != nullptr);

    std::cout << "\n\n********** Test netevent_sim provider load/unload while the extension is running. **********"
              << std::endl;
    auto start_time = std::chrono::high_resolution_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start_time)
               .count() < NETEVENT_EVENT_STRESS_TEST_TIMEOUT_SEC) {
        // Unload netevent_sim
        std::this_thread::sleep_for(std::chrono::seconds(5));
        REQUIRE(netevent_sim_driver.stop() == true);
        REQUIRE(netevent_sim_driver.unload() == true);

        // Sample the event count before reloading the driver,
        // after waiting for any pending events to be processed, so they don't count later.
        std::this_thread::sleep_for(std::chrono::seconds(10));
        uint32_t event_count_before = event_count;

        // Reload netevent_sim
        REQUIRE(
            netevent_sim_driver.create(L"netevent_sim", driver_service::get_driver_path("netevent_sim.sys").c_str()) ==
            true);
        REQUIRE(netevent_sim_driver.start() == true);

        // Test that the event count has increased.
        std::this_thread::sleep_for(std::chrono::seconds(5));
        REQUIRE(event_count > event_count_before);
    }

    std::cout << "\n\n********** Test extension load/unload while events are still being generated by the provider. "
                 "**********"
              << std::endl;
    start_time = std::chrono::high_resolution_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start_time)
               .count() < NETEVENT_EVENT_STRESS_TEST_TIMEOUT_SEC) {
        // Unload neteventebpfext
        std::this_thread::sleep_for(std::chrono::seconds(5));
        REQUIRE(neteventebpfext_driver.stop() == true);
        REQUIRE(neteventebpfext_driver.unload() == true);

        // Sample the event count before reloading the driver,
        // after waiting for any pending events to be processed, so they don't count later.
        std::this_thread::sleep_for(std::chrono::seconds(10));
        uint32_t event_count_before = event_count;

        // Reload neteventebpfext
        REQUIRE(
            neteventebpfext_driver.create(
                L"neteventebpfext", driver_service::get_driver_path("neteventebpfext.sys").c_str()) == true);
        REQUIRE(neteventebpfext_driver.start() == true);

        // Test that the event count has increased.
        std::this_thread::sleep_for(std::chrono::seconds(5));
        REQUIRE(event_count > event_count_before);
    }

    // Detach the program (link) from the attach point.
    int link_fd = bpf_link__fd(netevent_monitor_link);
    bpf_link_detach(link_fd);
    bpf_link__destroy(netevent_monitor_link);

    // Close ring buffer.
    ring_buffer__free(ring);

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

    // Attach to the eBPF ring buffer event map.
    bpf_map* netevent_events_map = bpf_object__find_map_by_name(object, "netevent_events_map");
    REQUIRE(netevent_events_map != nullptr);
    ring_buffer* ring =
        ring_buffer__new(bpf_map__fd(netevent_events_map), netevent_monitor_event_callback, nullptr, nullptr);
    REQUIRE(ring != nullptr);

    // Initialize structures required for bpf_prog_test_run_opts
    bpf_test_run_opts bpf_opts = {0};
    test_netevent_event_md_t test_netevent_ctx_in = {0};
    test_netevent_event_md_t test_netevent_ctx_out = {0};
    netevent_event_md_t& netevent_ctx_in = test_netevent_ctx_in.context;
    netevent_event_md_t& netevent_ctx_out = test_netevent_ctx_out.context;
    unsigned char test_data_in[MAX_PACKET_SIZE] = {0};
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
    unsigned char data_out[MAX_PACKET_SIZE] = {0};
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

    std::this_thread::sleep_for(std::chrono::seconds(5));
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

    // Free the ring buffer manager
    ring_buffer__free(ring);

    // Free the BPF object.
    bpf_object__close(object);

    // Stop and unload the neteventebpfext extension driver (NPI client).
    REQUIRE(neteventebpfext_driver.stop() == true);
    REQUIRE(neteventebpfext_driver.unload() == true);
}