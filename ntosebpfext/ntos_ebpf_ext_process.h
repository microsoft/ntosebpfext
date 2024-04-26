// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_ext.h"

/**
 * @brief Unregister PROCESS NPI providers.
 *
 */
void
ntos_ebpf_ext_process_unregister_providers();

/**
 * @brief Register PROCESS NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
ntos_ebpf_ext_process_register_providers();
