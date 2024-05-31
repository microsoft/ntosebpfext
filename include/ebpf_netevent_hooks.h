// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stddef.h>
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by neteventebpfext.sys for use by eBPF programs.

//// This structure is used to pass event data to the eBPF program.
typedef struct _netevent_event_md
{
    uint8_t* event_data_start; ///< Pointer to start of the data associated with the event.
    uint8_t* event_data_end;   ///< Pointer to end of the data associated with the event.

} netevent_event_md_t;

/*
 * @brief Write an event into the ring buffer.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_NETEVENT
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_NETEVENT
 *
 * @param[in] context \ref netevent_event_md_t
 * @return STATUS_SUCCESS insertion succeeded.
 * Value of STATUS_SUCCESS is 0x0.
 */
typedef int
netevent_event_hook_t(netevent_event_md_t* context);

// NetEvent helper functions.
#define NETEVENT_EXT_HELPER_FN_BASE 0xFFFF

#if !defined(__doxygen) && !defined(EBPF_HELPER)
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

typedef enum
{
    BPF_FUNC_netevent_push_event = NETEVENT_EXT_HELPER_FN_BASE + 1,
} ebpf_netevent_event_helper_id_t;

/**
 * @brief Push an event to the netevent event ring buffer.
 *
 * @param[in] context Event metadata.
 *
 * @retval =0 Succeeded inserting the event.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_netevent_push_event, (netevent_event_md_t * ctx));
#ifndef __doxygen
#define bpf_netevent_push_event ((bpf_netevent_push_event_t)BPF_FUNC_netevent_push_event)
#endif
