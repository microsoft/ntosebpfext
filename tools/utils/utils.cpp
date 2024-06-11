// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "utils.h"

#include <iostream>

driver_service::~driver_service()
{
    stop();
    unload();
}

// Function to get the full path to the given driver file.
std::wstring
driver_service::get_driver_path(const char* driver_name)
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
driver_service::create(const wchar_t* service_name, const wchar_t* driver_path)
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
driver_service::start()
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
driver_service::stop()
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
driver_service::unload()
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