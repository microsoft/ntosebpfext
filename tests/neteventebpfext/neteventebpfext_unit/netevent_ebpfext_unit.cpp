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

struct bpf_map* netevent_event_map;
struct bpf_map* command_map;
static uint32_t event_count = 0;

// Lock-free event ring buffer, used to store events without blocking the the eBPF callback.
struct event_t
{
    size_t size;
    uint8_t* data;
};
typed_ring_buffer<event_t, MAX_EVENTS_COUNT, false> event_buffer; // MAX_EVENTS_COUNT events, no overwriting.
std::atomic<bool> stop_worker = false;                            // Stop flag for the event processing worker thread.

void
_dump_event(const char* event_descr, void* data, size_t size, bool print_str = false)
{
    // Simply dump the event data as hex bytes.
    uint8_t event_type = static_cast<uint8_t>(*reinterpret_cast<const std::byte*>(data));

    if (print_str) {
        std::cout << std::endl
                  << ">>>" << event_descr << " - type[" << event_type << "], " << size << " message: { " << data << " }"
                  << std::endl;
    } else {
        std::cout << std::endl << ">>>" << event_descr << " - type[" << event_type << "], " << size << " bytes: { ";
        for (size_t i = 0; i < size; ++i) {
            std::cout << std::setw(2) << std::setfill('0') << std::hex
                      << static_cast<int>(reinterpret_cast<const std::byte*>(data)[i]) << " ";
        }
    }

    std::cout << "}" << std::endl;
    std::cout << std::dec; // Reset to decimal.
}

// Worker thread to process events that are stored in the deferred ring buffer storage.
void
process_events()
{
    while (!stop_worker) {
        event_t event;
        while (event_buffer.read(event)) {
            _dump_event("netevent_event", event.data, event.size, true);
            delete[] event.data;
        }
        // Yield to avoid busy waiting.
        std::this_thread::yield();
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

    // Queue the event for deferred processing, unblocking the eBPF callback.
    event_count++;
    uint8_t* data_copy = new uint8_t[size];
    if (data_copy != nullptr) {
        memcpy(
            data_copy,
            data,
            size); // In a real scenario, memory management would need to be more sophisticated, to avoid fragmentation.
        if (!event_buffer.write({size, data_copy})) {
            delete[] data_copy;
            return -1;
        }
        return 0;
    }

    return -1;
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

    // Start worker thread for processing incoming events that are stored in the ring buffer by the callback.
    std::thread worker(process_events);

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
    // Stop the event processing worker thread.
    if (worker.joinable()) {
        stop_worker = true;
        worker.join();
    }
    REQUIRE(event_count >= MAX_EVENTS_COUNT);
    REQUIRE(timeout > 0); // Ensure the test didn't time out.

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