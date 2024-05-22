// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "framework.h"

#include <atomic>
#include <string>

/// @brief
/// General purpose lock-free typed ring-buffer template.
/// @tparam T Type of the record to store in the buffer.
/// @tparam max_size Maximum size of the buffer.
/// @tparam overwrite Flag to indicate if the buffer should overwrite the oldest record when full.
template <typename T, size_t max_size, bool overwrite> class typed_ring_buffer
{
  private:
    std::array<T, max_size> buffer = {};
    std::atomic<size_t> write_index = 0;
    std::atomic<size_t> read_index = 0;

  public:
    bool
    write(const T& item)
    {
        size_t current_write_index = write_index.load(std::memory_order_relaxed);
        size_t next_write_index = current_write_index + 1;

        if (!overwrite) {
            size_t current_read_index = read_index.load(std::memory_order_acquire);
            if (next_write_index - current_read_index > max_size) {
                return false;
            }
        }

        buffer[current_write_index % max_size] = item;
        write_index.store(next_write_index, std::memory_order_release);
        return true;
    }

    bool
    read(T& item)
    {
        size_t current_read_index = read_index.load(std::memory_order_relaxed);
        if (current_read_index == write_index.load(std::memory_order_acquire)) {
            return false;
        }

        item = buffer[current_read_index % max_size];
        read_index.store(current_read_index + 1, std::memory_order_release);
        return true;
    }
};

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