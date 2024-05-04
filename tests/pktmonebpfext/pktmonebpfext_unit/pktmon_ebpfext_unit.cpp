// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN
#include "catch_wrapper.hpp"
#include "cxplat_fault_injection.h"
#include "cxplat_passed_test_log.h"
#include "ebpf_pktmon_hooks.h"
#include "pktmon_ebpf_ext_helper.h"
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
#define MAX_EVENTS_COUNT 100000
#define PKTMON_EVENT_TEST_TIMEOUT_SEC 90

struct bpf_map* pktmon_event_map;
struct bpf_map* command_map;
static uint32_t event_count = 0;

// Function to start a driver service
bool
start_driver_service(const char* service_name, const char* driver_path)
{
    SC_HANDLE scm, service;

    // Convert narrow strings to wide strings
    std::wstring wide_service_name;
    wide_service_name.assign(service_name, service_name + strlen(service_name));
    std::wstring wide_driver_path;
    wide_driver_path.assign(driver_path, driver_path + strlen(driver_path));

    // Open the Service Control Manager
    scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        std::cerr << "Failed to open Service Control Manager." << std::endl;
        return false;
    }

    // Create the driver service
    service = CreateService(
        scm,
        wide_service_name.c_str(),
        wide_service_name.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        wide_driver_path.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);
    if (!service) {
        std::cerr << "Failed to create service." << std::endl;
        CloseServiceHandle(scm);
        return false;
    }

    // Start the service
    if (!StartService(service, 0, nullptr)) {
        std::cerr << "Failed to start service." << std::endl;
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    std::cout << "Service started successfully." << std::endl;

    // Close handles
    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return true;
}

// Function to stop a driver service
bool
stop_driver_service(const char* service_name)
{
    SC_HANDLE scm, service;
    SERVICE_STATUS status;

    // Convert narrow string to wide string
    std::wstring wide_service_name;
    wide_service_name.assign(service_name, service_name + strlen(service_name));

    // Open the Service Control Manager
    scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        std::cerr << "Failed to open Service Control Manager." << std::endl;
        return false;
    }

    // Open the driver service
    service = OpenService(scm, wide_service_name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
        std::cerr << "Failed to open service." << std::endl;
        CloseServiceHandle(scm);
        return false;
    }

    // Send a stop control to the service
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        std::cerr << "Failed to stop service." << std::endl;
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    std::cout << "Service stopped successfully." << std::endl;

    // Close handles
    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return true;
}

// Function to unload/delete a driver service
bool
unload_driver(const char* service_name)
{
    SC_HANDLE scm, service;
    SERVICE_STATUS status;

    // Convert narrow string to wide string
    std::wstring wide_service_name;
    wide_service_name.assign(service_name, service_name + strlen(service_name));

    // Open the Service Control Manager
    scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        std::cerr << "Failed to open Service Control Manager." << std::endl;
        return false;
    }

    // Open the driver service
    service = OpenService(scm, wide_service_name.c_str(), SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!service) {
        std::cerr << "Failed to open service." << std::endl;
        CloseServiceHandle(scm);
        return false;
    }

    // Send a stop control to the service
    ControlService(service, SERVICE_CONTROL_STOP, &status);

    // Delete the service
    if (!DeleteService(service)) {
        std::cerr << "Failed to delete service." << std::endl;
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    std::cout << "Service deleted successfully." << std::endl;

    // Close handles
    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return true;
}

typedef struct
{
    unsigned char* event_data_start; ///< Pointer to start of the data associated with the event.
    unsigned char* event_data_end; ///< Pointer to end of the data associated with the event (i.e. first byte *outside*
                                   ///< the memory range).
} pktmon_event_info_t;

typedef struct test_pktmon_event_client_context_t
{
    pktmonebpfext_helper_base_client_context_t base;
    pktmon_event_md_t pktmon_event_context;
} test_pktmon_event_client_context_t;

_Must_inspect_result_ ebpf_result_t
pktmonebpfext_unit_invoke_pktmon_event_program(
    _In_ const void* client_pktmon_event_context, _In_ const void* context, _Out_ uint32_t* result)
{
    pktmon_event_md_t* pktmon_event_context = (pktmon_event_md_t*)context;
    test_pktmon_event_client_context_t* client_context =
        (test_pktmon_event_client_context_t*)client_pktmon_event_context;

    client_context->pktmon_event_context = *pktmon_event_context;
    *result = STATUS_ACCESS_DENIED;
    return EBPF_SUCCESS;
}

TEST_CASE("pktmon_event_invoke", "[pktmonebpfext]")
{
    ebpf_extension_data_t npi_specific_characteristics = {};
    test_pktmon_event_client_context_t client_context = {};

    pktmonebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)pktmonebpfext_unit_invoke_pktmon_event_program,
        (pktmonebpfext_helper_base_client_context_t*)&client_context);
}

void
_dump_event(const char* event_descr, void* data, size_t size)
{
    uint8_t event_type = static_cast<uint8_t>(*reinterpret_cast<const std::byte*>(data));

    std::cout << std::endl << ">>>" << event_descr << " - type[" << event_type << "], " << size << " bytes: { ";
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex
                  << static_cast<int>(reinterpret_cast<const std::byte*>(data)[i]) << " ";
    }
    std::cout << "}" << std::endl;
    std::cout << std::dec; // Reset to decimal.
}

int
pktmon_monitor_event_callback(void* ctx, void* data, size_t size)
{
    UNREFERENCED_PARAMETER(ctx);
    if (size != sizeof(pktmon_event_info_t)) {
        return 0;
    }

    // Trace the event
    event_count++;
    pktmon_event_info_t* event = (pktmon_event_info_t*)data;
    _dump_event("pktmon_event", event->event_data_start, event->event_data_end - event->event_data_start);

    return 0;
}

TEST_CASE("pktmon_event_simulate", "[pktmonebpfext]")
{
    // Load and start pktmon simulator driver.
    REQUIRE(start_driver_service("pktmon_sim", "pktmon_sim.sys"));

    // Load and start pktmonebpfext extension driver.
    REQUIRE(start_driver_service("pktmonebpfext", "pktmonebpfext.sys"));

    // Load pktmon_monitor.sys BPF program.
    struct bpf_object* object = bpf_object__open("pktmon_monitor.sys");
    REQUIRE(object != nullptr);

    int res = bpf_object__load(object);
    REQUIRE(res == 0);

    // Find and attach to the pktmon_monitor BPF program.
    auto pktmon_monitor = bpf_object__find_program_by_name(object, "PktmonMonitor");
    REQUIRE(pktmon_monitor != nullptr);
    auto pktmon_monitor_link = bpf_program__attach(pktmon_monitor);
    REQUIRE(pktmon_monitor_link != nullptr);

    // Attach to ring buffer.
    bpf_map* pktmon_events_map = bpf_object__find_map_by_name(object, "pktmon_events_map");
    REQUIRE(pktmon_events_map != nullptr);
    auto ring = ring_buffer__new(bpf_map__fd(pktmon_events_map), pktmon_monitor_event_callback, nullptr, nullptr);
    REQUIRE(ring != nullptr);

    // Wait for the number of expected events or a timeout.
    int timeout = PKTMON_EVENT_TEST_TIMEOUT_SEC;
    while (event_count < MAX_EVENTS_COUNT && timeout > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    REQUIRE(event_count >= MAX_EVENTS_COUNT);
    REQUIRE(timeout > 0);

    // First, stop and unload the pktmon simulator driver (NPI provider).
    REQUIRE(stop_driver_service("pktmon_sim"));
    REQUIRE(unload_driver("pktmon_sim"));

    // Stop and unload the pktmonebpfext extension driver (NPI client).
    REQUIRE(stop_driver_service("pktmonebpfext"));
    REQUIRE(unload_driver("pktmonebpfext"));

    // Detach from the attach point.
    int link_fd = bpf_link__fd(pktmon_monitor_link);
    bpf_link_detach(link_fd);
    bpf_link__destroy(pktmon_monitor_link);

    // Close ring buffer.
    ring_buffer__free(ring);

    // Free the BPF object.
    bpf_object__close(object);
}