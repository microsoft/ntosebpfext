// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stddef.h>
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by pktmonebpfext.sys for use by eBPF programs.

#define NOTIFY_EVENT_TYPE_PKTMON 100 // TBD: Update this value to be compatible with Cilium's enums.

// This structure is used to pass event data to the eBPF program.
typedef struct _pktmon_event_md
{
    uint8_t* event_data_start; ///< Pointer to start of the data associated with the event.
    uint8_t* event_data_end;   ///< Pointer to end of the data associated with the event.

} pktmon_event_md_t;

/*
 * @brief Handle process creation and deletion.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_PKTMON
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_PKTMON
 *
 * @param[in] context \ref pktmon_event_md_t
 * @return STATUS_SUCCESS to permit the operation, or a failure NTSTATUS value to deny the operation.
 * Value of STATUS_SUCCESS is 0x0.
 */
typedef int
pktmon_event_hook_t(pktmon_event_md_t* context);

// Pktmon helper functions.
#define PKTMON_EXT_HELPER_FN_BASE 0xFFFF

#if !defined(__doxygen) && !defined(EBPF_HELPER)
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

typedef enum
{
    BPF_FUNC_pktmon_push_event = PKTMON_EXT_HELPER_FN_BASE + 1,
} ebpf_pktmon_event_helper_id_t;

/**
 * @brief Push an event to the pktmon event ring buffer.
 *
 * @param[in] context Event metadata.
 * @param[in] data Pointer to the buffer containing the event data.
 * @param[in] data_length The length of the event data.
 *
 * @retval >=0 The length of the image path.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_pktmon_push_event, (pktmon_event_md_t * ctx, uint8_t* data, uint32_t data_length));
#ifndef __doxygen
#define bpf_pktmon_push_event ((bpf_pktmon_push_event_t)BPF_FUNC_pktmon_push_event)
#endif
