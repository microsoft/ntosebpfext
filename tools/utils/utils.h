// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "framework.h"

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <string>

/// @brief
/// Helper class to manage driver services.
/// This class is used to create, start, stop and unload driver services.
class driver_service
{
  private:
    SC_HANDLE handle = NULL;

  public:
    driver_service() = default;
    ~driver_service() noexcept;

    SC_HANDLE
    getHandle() const { return handle; };

    /// @brief
    /// Function to get the full path to the given driver file.
    /// @param driver_name Name of the driver file.
    /// @return Full path to the driver file.
    static std::wstring
    get_driver_path(const char* driver_name);

    /// @brief
    /// Function to create a driver service.
    /// @param service_name Name of the service.
    /// @param driver_path Path to the driver file.
    /// @return true if the service is created successfully, false otherwise.
    bool
    create(const wchar_t* service_name, const wchar_t* driver_path);

    /// @brief
    /// Function to start a driver service.
    /// @return true if the service is started successfully, false otherwise.
    bool
    start();

    /// @brief
    /// Function to stop a driver service.
    /// @return true if the service is stopped successfully, false otherwise.
    bool
    stop();

    /// @brief
    /// Function to unload a driver.
    /// @return true if the driver is unloaded successfully, false otherwise.
    bool
    unload();
};
