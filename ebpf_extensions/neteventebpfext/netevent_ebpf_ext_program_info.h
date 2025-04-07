// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_ext.h"
#include "ebpf_extension.h"
#include "ebpf_netevent_hooks.h"
#include "ebpf_netevent_program_attach_type_guids.h"
#include "ebpf_program_types.h"

#define BPF_ATTACH_TYPE_NETEVENT 99900
#define BPF_PROG_TYPE_NETEVENT 99901

static const ebpf_helper_function_prototype_t _netevent_event_ebpf_extension_helper_function_prototype[] = {
    {.header =
         {.version = EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION,
          .size = EBPF_HELPER_FUNCTION_PROTOTYPE_CURRENT_VERSION_SIZE},
     .helper_id = EBPF_MAX_GENERAL_HELPER_FUNCTION + 1,
     .name = "bpf_netevent_push_event",
     .return_type = EBPF_RETURN_TYPE_INTEGER,
     .arguments = {EBPF_ARGUMENT_TYPE_PTR_TO_CTX}}};

static const ebpf_context_descriptor_t _ebpf_netevent_program_context_descriptor = {
    (int)sizeof(netevent_event_md_t),
    EBPF_OFFSET_OF(netevent_event_md_t, data),
    EBPF_OFFSET_OF(netevent_event_md_t, data_end),
    EBPF_OFFSET_OF(netevent_event_md_t, data_meta),
};

static const ebpf_program_type_descriptor_t _ebpf_program_type_netevent_guid = {
    .header =
        {.version = EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION,
         .size = EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE},
    .name = "netevent_monitor",
    .context_descriptor = &_ebpf_netevent_program_context_descriptor,
    .program_type = EBPF_PROGRAM_TYPE_NETEVENT_GUID,
    .bpf_prog_type = BPF_PROG_TYPE_NETEVENT,
    .is_privileged = 0};

static const ebpf_program_info_t _ebpf_netevent_event_program_info = {
    .header =
        {.version = EBPF_PROGRAM_INFORMATION_CURRENT_VERSION, .size = EBPF_PROGRAM_INFORMATION_CURRENT_VERSION_SIZE},
    .program_type_descriptor = &_ebpf_program_type_netevent_guid,
    .count_of_program_type_specific_helpers = EBPF_COUNT_OF(_netevent_event_ebpf_extension_helper_function_prototype),
    .program_type_specific_helper_prototype = _netevent_event_ebpf_extension_helper_function_prototype,
    .count_of_global_helpers = 0,
    .global_helper_prototype = NULL};

static const ebpf_program_section_info_t _ebpf_netevent_event_section_info[] = {
    {
        .header =
            {.version = EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION,
             .size = EBPF_PROGRAM_SECTION_INFORMATION_CURRENT_VERSION_SIZE},
        .section_name = L"netevent_monitor",
        .program_type = &EBPF_PROGRAM_TYPE_NETEVENT,
        .attach_type = &EBPF_ATTACH_TYPE_NETEVENT,
        .bpf_program_type = BPF_PROG_TYPE_NETEVENT,
        .bpf_attach_type = BPF_ATTACH_TYPE_NETEVENT,
    },
};
