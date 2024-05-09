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
#define MAX_EVENTS_COUNT 10000
#define PKTMON_EVENT_TEST_TIMEOUT_SEC 90

struct bpf_map* pktmon_event_map;
struct bpf_map* command_map;
static uint32_t event_count = 0;

// Lock-free event ring buffer, used to store events without blocking the the eBPF callback.
struct event_t
{
    size_t size;
    uint8_t* data;
};
template <typename T, size_t max_size, bool overwrite> class event_ring_buffer
{
  private:
    std::array<T, max_size> buffer = {};
    std::atomic<size_t> write_index = 0;
    std::atomic<size_t> read_index = 0;

  public:
    bool
    write(const T& item)
    {
        size_t next_write_index = write_index + 1;
        if (!overwrite && next_write_index - read_index == max_size) {
            return false;
        }
        buffer[write_index++ % max_size] = item;
        return true;
    }

    bool
    read(T& item)
    {
        if (read_index == write_index) {
            return false;
        }
        item = buffer[read_index++ % max_size];
        return true;
    }
};
event_ring_buffer<event_t, 10000, false> event_buffer; // 10K events, no overwriting.
std::atomic<bool> stop_worker = false;                 // Stop flag for the event processing worker thread.

class driver_helper
{
  private:
    SC_HANDLE handle = NULL;

  public:
    driver_helper() {}
    ~driver_helper()
    {
        stop_driver_service();
        unload_driver();
    }

    SC_HANDLE
    getHandle() const { return handle; }

    // Function to get the full path to the given driver file.
    static std::wstring
    get_driver_path(const char* driver_name)
    {
        wchar_t exePath[MAX_PATH];
        GetModuleFileName(nullptr, exePath, MAX_PATH);

        std::wstring driverPath(exePath);

        // Find the last backslash in the executable path to get the directory
        size_t pos = driverPath.find_last_of(L"\\");
        if (pos != std::wstring::npos) {
            // Replace the executable name with the driver name
            std::wstring driverNameWide;
            driverNameWide.assign(driver_name, driver_name + strlen(driver_name));
            driverPath = driverPath.substr(0, pos + 1) + driverNameWide;
        }

        return driverPath;
    }

    // Function to create a driver service.
    bool
    create_driver_service(const wchar_t* service_name, const wchar_t* driver_path)
    {
        bool ret = true;
        SC_HANDLE scm;

        // Open the Service Control Manager
        scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) {
            std::cerr << "Failed to open Service Control Manager." << std::endl;
            return false;
        }

        // Create the driver service.
        handle = CreateService(
            scm,
            service_name,
            service_name,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driver_path,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);
        if (!handle) {
            std::cerr << "Failed to create service." << std::endl;
            ret = false;
        }

        // Close the SCM handle.
        CloseServiceHandle(scm);

        return ret;
    }

    // Function to start a driver service.
    bool
    start_driver_service()
    {
        if (handle == NULL) {
            return false;
        }

        // Start the service
        if (!StartService(handle, 0, nullptr)) {
            std::cerr << "Failed to start service. Last error: " << GetLastError() << std::endl;
            return false;
        }
        std::cout << "Service started successfully." << std::endl;

        return true;
    }

    // Function to stop a driver service.
    bool
    stop_driver_service()
    {
        SERVICE_STATUS status;

        if (handle == NULL) {
            return true;
        }

        // Send a stop control to the service
        if (!ControlService(handle, SERVICE_CONTROL_STOP, &status)) {
            std::cerr << "Failed to stop service. Last error: " << GetLastError() << std::endl;
            return false;
        }
        std::cout << "Service stopped successfully." << std::endl;

        return true;
    }

    // Function to unload/delete a driver service.
    bool
    unload_driver()
    {
        SERVICE_STATUS status;

        if (handle == NULL) {
            return true;
        }

        // Send a stop control to the service
        ControlService(handle, SERVICE_CONTROL_STOP, &status);
        if (status.dwCurrentState != SERVICE_STOPPED) {
            std::cerr << "Failed to stop service. Last error: " << GetLastError() << std::endl;
            return false;
        }

        // Delete the service
        if (!DeleteService(handle)) {
            std::cerr << "Failed to delete service. Last error: " << GetLastError() << std::endl;
            return false;
        }
        std::cout << "Service deleted successfully." << std::endl;

        // Close the service handle
        if (CloseServiceHandle(handle)) {
            handle = NULL;
            return true;
        }

        return false;
    }
};

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

    // Load and start pktmonebpfext extension driver.
    driver_helper pktmonebpfext_driver;
    REQUIRE(
        pktmonebpfext_driver.create_driver_service(
            L"pktmonebpfext", driver_helper::get_driver_path("pktmonebpfext.sys").c_str()) == true);
    REQUIRE(pktmonebpfext_driver.start_driver_service() == true);

    pktmonebpf_ext_helper_t helper(
        &npi_specific_characteristics,
        (_ebpf_extension_dispatch_function)pktmonebpfext_unit_invoke_pktmon_event_program,
        (pktmonebpfext_helper_base_client_context_t*)&client_context);

    // Stop and unload the pktmonebpfext extension driver (NPI client).
    REQUIRE(pktmonebpfext_driver.stop_driver_service() == true);
    REQUIRE(pktmonebpfext_driver.unload_driver() == true);
}

void
_dump_event(const char* event_descr, void* data, size_t size)
{
    // Simply dump the event data as hex bytes.
    uint8_t event_type = static_cast<uint8_t>(*reinterpret_cast<const std::byte*>(data));

    std::cout << std::endl << ">>>" << event_descr << " - type[" << event_type << "], " << size << " bytes: { ";
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex
                  << static_cast<int>(reinterpret_cast<const std::byte*>(data)[i]) << " ";
    }
    std::cout << "}" << std::endl;
    std::cout << std::dec; // Reset to decimal.
}

// Worker thread to process events that are stored in the deferred ring buffer storage.
void
process_events()
{
    event_t event;
    while (!stop_worker) {
        while (event_buffer.read(event)) {
            _dump_event("pktmon_event", event.data, event.size);
            delete[] event.data; // Delete the data after processing the event.
        }
        // Yield to avoid busy waiting.
        std::this_thread::yield();
    }
}

int
pktmon_monitor_event_callback(void* ctx, void* data, size_t size)
{
    // Parameter checks.
    UNREFERENCED_PARAMETER(ctx);
    if (data == nullptr || size == 0) {
        return 0;
    }

    // Check if this event is actually a pktmon event (i.e. first byte is NOTIFY_EVENT_TYPE_PKTMON).
    uint8_t event_type = static_cast<uint8_t>(*reinterpret_cast<const std::byte*>(data));
    if (event_type != NOTIFY_EVENT_TYPE_PKTMON) {
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

TEST_CASE("pktmon_event_simulation", "[pktmonebpfext]")
{
    // First, load the pktmon simulator driver (NPI provider).
    driver_helper pktmon_sim_driver;
    REQUIRE(
        pktmon_sim_driver.create_driver_service(
            L"pktmon_sim", driver_helper::get_driver_path("pktmon_sim.sys").c_str()) == true);
    REQUIRE(pktmon_sim_driver.start_driver_service() == true);

    // Load and start pktmonebpfext extension driver.
    driver_helper pktmonebpfext_driver;
    REQUIRE(
        pktmonebpfext_driver.create_driver_service(
            L"pktmonebpfext", driver_helper::get_driver_path("pktmonebpfext.sys").c_str()) == true);
    REQUIRE(pktmonebpfext_driver.start_driver_service() == true);

    // Load the PktmonMonitor native BPF program.
    struct bpf_object* object = bpf_object__open("pktmon_monitor.sys");
    REQUIRE(object != nullptr);

    int res = bpf_object__load(object);
    REQUIRE(res == 0);

    // Find and attach to the pktmon_monitor BPF program.
    auto pktmon_monitor = bpf_object__find_program_by_name(object, "PktmonMonitor");
    REQUIRE(pktmon_monitor != nullptr);
    auto pktmon_monitor_link = bpf_program__attach(pktmon_monitor);
    REQUIRE(pktmon_monitor_link != nullptr);

    // Start worker thread for processing incoming events that are stored in the ring buffer by the callback.
    std::thread worker(process_events);

    // Attach to the eBPF ring buffer event map.
    bpf_map* pktmon_events_map = bpf_object__find_map_by_name(object, "pktmon_events_map");
    REQUIRE(pktmon_events_map != nullptr);
    auto ring = ring_buffer__new(bpf_map__fd(pktmon_events_map), pktmon_monitor_event_callback, nullptr, nullptr);
    REQUIRE(ring != nullptr);

    // Wait for the number of expected events or the test's max run time.
    int timeout = PKTMON_EVENT_TEST_TIMEOUT_SEC;
    while (event_count < MAX_EVENTS_COUNT && timeout > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    REQUIRE(event_count >= MAX_EVENTS_COUNT);
    REQUIRE(timeout > 0); // Ensure the test didn't time out.

    // Detach the program (link) from the attach point.
    int link_fd = bpf_link__fd(pktmon_monitor_link);
    bpf_link_detach(link_fd);
    bpf_link__destroy(pktmon_monitor_link);

    // Close ring buffer.
    ring_buffer__free(ring);

    // Free the BPF object.
    bpf_object__close(object);

    // First, stop and unload the pktmon simulator driver (NPI provider).
    REQUIRE(pktmon_sim_driver.stop_driver_service() == true);
    REQUIRE(pktmon_sim_driver.unload_driver() == true);

    // Stop and unload the pktmonebpfext extension driver (NPI client).
    REQUIRE(pktmonebpfext_driver.stop_driver_service() == true);
    REQUIRE(pktmonebpfext_driver.unload_driver() == true);

    // Stop the event processing worker thread.
    if (worker.joinable()) {
        stop_worker = true;
        worker.join();
    }
}