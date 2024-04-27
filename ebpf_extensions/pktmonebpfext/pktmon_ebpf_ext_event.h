// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_ext.h"

/**
 * @brief Register EVENT NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
ebpf_ext_register_pktmon();

/**
 * @brief Unregister EVENT NPI providers.
 *
 */
void
ebpf_ext_unregister_pktmon();
