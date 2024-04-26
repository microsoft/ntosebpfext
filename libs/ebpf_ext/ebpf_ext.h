// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @file
 * @brief Header file for structures/prototypes of the driver.
 */

#include "ebpf_ext_hook_provider.h"
#include "ebpf_ext_prog_info_provider.h"
#include "ebpf_ext_tracelog.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_program_types.h"
#include "ebpf_windows.h"

#include <guiddef.h>
#include <netioapi.h>
#include <netiodef.h>

#define EBPF_EXTENSION_POOL_TAG 'bEtN'
#define EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

struct _ebpf_extension_hook_client;

extern DEVICE_OBJECT* _ebpf_ext_driver_device_object;

/**
 * @brief Register extension NPI providers with eBPF core.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
ebpf_ext_register_providers();

/**
 * @brief Unregister extension NPI providers from eBPF core.
 *
 */
void
ebpf_ext_unregister_providers();
