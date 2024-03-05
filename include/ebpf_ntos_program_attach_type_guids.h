// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_windows.h"

#ifdef __cplusplus
extern "C"
{
#endif
    //
    // Attach Types.
    //

    /** @brief Attach type for handling process creation and destruction events.
     *
     * Program type: \ref EBPF_ATTACH_TYPE_PROCESS
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_PROCESS = {
        0x66e20687, 0x9805, 0x4458, {0xa0, 0xdb, 0x38, 0xe2, 0x20, 0xd3, 0x16, 0x85}};

    //
    // Program Types.
    //

#define EBPF_PROGRAM_TYPE_PROCESS_GUID                                                 \
    {                                                                                  \
        0x22ea7b37, 0x1043, 0x4d0d, { 0xb6, 0x0d, 0xca, 0xfa, 0x1c, 0x7b, 0x63, 0x8e } \
    }

    /** @brief Program type for handling process creation and destruction events.
     *
     * eBPF program prototype: \ref process_md_t
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_PRCOESS
     *
     * Helpers available: see bpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_PROCESS = EBPF_PROGRAM_TYPE_PROCESS_GUID;

#ifdef __cplusplus
}
#endif
