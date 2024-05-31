// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN
#include "catch_wrapper.hpp"
#include "cxplat_fault_injection.h"
#include "cxplat_passed_test_log.h"
#include "ebpf_netevent_hooks.h"
#include "netevent_ebpf_ext_helper.h"
#include "utils.h"
#include "watchdog.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <iostream>
#include <string>
#include <thread>

struct _DEVICE_OBJECT* _ebpf_ext_driver_device_object;

CATCH_REGISTER_LISTENER(_watchdog)
CATCH_REGISTER_LISTENER(cxplat_passed_test_log)

#define EBPF_EVENTS_MAP_NAME "cilium_events"
#define DEFAULT_MAP_PIN_PATH_PREFIX "/ebpf/global/"
#define EVENTS_MAP_SIZE \
    (512 * 1024) // NOTE: must be kept in sync with the Cilium BPF code, in 'cnc\cilium\bpf\lib\events.h'.
#define MAX_EVENTS_COUNT 1000
#define NETEVENT_EVENT_TEST_TIMEOUT_SEC 90
#define NOTIFY_EVENT_TYPE_NETEVENT 100 // The event type we want to process (matching the one emitted by netevent_sim).

struct bpf_map* netevent_event_map;
struct bpf_map* command_map;
static volatile uint32_t event_count = 0;

void
_dump_event(const char* event_descr, void* data, size_t size, bool print_str = false)
{
    // Simply dump the event data as hex bytes.
    uint8_t event_type = static_cast<uint8_t>(*reinterpret_cast<const std::byte*>(data));

    if (print_str) {
        // Print the buffer as a string
        std::cout << "\r>>> " << event_descr << " - type[" << (int)event_type << "], " << size << " bytes - message: { "
                  << ((char*)data + 1) << " }" << std::flush;
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
    if (data == nullptr || size == 0) {
        return 0;
    }

    // Check if this event is actually a netevent event (i.e. first byte is NOTIFY_EVENT_TYPE_NETEVENT).
    uint8_t event_type = static_cast<uint8_t>(*reinterpret_cast<const std::byte*>(data));
    if (event_type != NOTIFY_EVENT_TYPE_NETEVENT) {
        return 0;
    }
    event_count++;
    _dump_event("netevent_event", data, size, true);

    return 0;
}

TEST_CASE("netevent_event_simulation", "[neteventebpfext]")
{
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
    auto netevent_monitor = bpf_object__find_program_by_name(object, "NetEventMonitor");
    REQUIRE(netevent_monitor != nullptr);
    auto netevent_monitor_link = bpf_program__attach(netevent_monitor);
    REQUIRE(netevent_monitor_link != nullptr);

    // Attach to the eBPF ring buffer event map.
    bpf_map* netevent_events_map = bpf_object__find_map_by_name(object, "netevent_events_map");
    REQUIRE(netevent_events_map != nullptr);
    auto ring = ring_buffer__new(bpf_map__fd(netevent_events_map), netevent_monitor_event_callback, nullptr, nullptr);
    REQUIRE(ring != nullptr);

    // Wait for the number of expected events or the test's max run time.
    int timeout = NETEVENT_EVENT_TEST_TIMEOUT_SEC;
    while (event_count < MAX_EVENTS_COUNT && timeout-- > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Test the event count and ensure the test didn't time out.
    REQUIRE(event_count >= MAX_EVENTS_COUNT);
    REQUIRE(timeout > 0);

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