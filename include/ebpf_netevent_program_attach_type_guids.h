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
#define EBPF_ATTACH_TYPE_NETEVENT_GUID                                                 \
    {                                                                                  \
        0x68011b08, 0xab6b, 0x4b46, { 0x85, 0xe4, 0x67, 0xba, 0xe1, 0xaf, 0xe7, 0x41 } \
    }

    /** @brief Attach type for handling process creation and destruction events.
     *
     * Program type: \ref EBPF_ATTACH_TYPE_NETEVENT
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_NETEVENT = EBPF_ATTACH_TYPE_NETEVENT_GUID;

    //
    // Program Types.
    //
#define EBPF_PROGRAM_TYPE_NETEVENT_GUID                                                \
    {                                                                                  \
        0xfc4adc85, 0x49c3, 0x4f0a, { 0x83, 0x93, 0xfa, 0xcc, 0xe8, 0x9c, 0xde, 0x91 } \
    }

    /** @brief Program type for handling process creation and destruction events.
     *
     * eBPF program prototype: \ref netevent_event_md_t
     *
     * Attach type(s): \ref EBPF_PROGRAM_TYPE_NETEVENT
     *
     * Helpers available: see bpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_NETEVENT = EBPF_PROGRAM_TYPE_NETEVENT_GUID;

#ifdef __cplusplus
}
#endif
