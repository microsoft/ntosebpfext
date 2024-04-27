// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_extension.h"
#include "ebpf_pktmon_hooks.h"
#include "ebpf_pktmon_program_attach_type_guids.h"
#include "ebpf_program_types.h"

#define EBPF_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))
#define EBPF_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))
#define EBPF_FROM_FIELD(s, m, o) (s*)((uint8_t*)o - EBPF_OFFSET_OF(s, m))
#define BPF_ATTACH_TYPE_PKTMON 99900
#define BPF_PROG_TYPE_PKTMON 99901

// Process program information.
static const ebpf_helper_function_prototype_t _pktmon_event_ebpf_extension_helper_function_prototype[] = {
    {.header =
         {.version = EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION,
          .size = EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_SIZE},
     .helper_id = EBPF_MAX_GENERAL_HELPER_FUNCTION + 1,
     .name = "bpf_pktmon_push_event",
     .return_type = EBPF_RETURN_TYPE_INTEGER,
     .arguments = {
         EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
         EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM,
         EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM}}};

static const ebpf_context_descriptor_t _ebpf_pktmon_program_context_descriptor = {
    (int)sizeof(pktmon_event_md_t),
    EBPF_OFFSET_OF(pktmon_event_md_t, event_data_start),
    EBPF_OFFSET_OF(pktmon_event_md_t, event_data_end),
    -1,
};

static const ebpf_program_type_descriptor_t _ebpf_program_type_pktmon_guid = {
    .header =
        {.version = EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION,
         .size = EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE},
    .name = "pktmon_monitor",
    .context_descriptor = &_ebpf_pktmon_program_context_descriptor,
    .program_type = EBPF_PROGRAM_TYPE_PKTMON_GUID,
    .bpf_prog_type = BPF_PROG_TYPE_PKTMON,
    .is_privileged = 0};

static const ebpf_program_info_t _ebpf_pktmon_event_program_info = {
    .header =
        {.version = EBPF_PROGRAM_INFORMATION_CURRENT_VERSION, .size = EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_SIZE},
    .program_type_descriptor = &_ebpf_program_type_pktmon_guid,
    .count_of_program_type_specific_helpers = EBPF_COUNT_OF(_pktmon_event_ebpf_extension_helper_function_prototype),
    .program_type_specific_helper_prototype = _pktmon_event_ebpf_extension_helper_function_prototype,
    .count_of_global_helpers = 0,
    .global_helper_prototype = NULL};

static const ebpf_program_section_info_t _ebpf_pktmon_event_section_info[] = {
    {
        .header =
            {.version = EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION,
             .size = EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION_SIZE},
        .section_name = L"pktmon_monitor",
        .program_type = &EBPF_PROGRAM_TYPE_PKTMON,
        .attach_type = &EBPF_ATTACH_TYPE_PKTMON,
        .bpf_program_type = BPF_PROG_TYPE_PKTMON,
        .bpf_attach_type = BPF_ATTACH_TYPE_PKTMON,
    },
};
