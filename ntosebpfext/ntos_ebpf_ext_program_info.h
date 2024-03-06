// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_extension.h"
#include "ebpf_program_types.h"

#define EBPF_COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))
#define EBPF_OFFSET_OF(s, m) (((size_t) & ((s*)0)->m))
#define EBPF_FROM_FIELD(s, m, o) (s*)((uint8_t*)o - EBPF_OFFSET_OF(s, m))

// Process program information.
static const ebpf_helper_function_prototype_t _process_ebpf_extension_helper_function_prototype[] = {
    {EBPF_MAX_GENERAL_HELPER_FUNCTION + 1,
     "bpf_process_get_image_path",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_CTX, EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM, EBPF_ARGUMENT_TYPE_CONST_SIZE}},
};

static const ebpf_context_descriptor_t _ebpf_process_context_descriptor = {
    sizeof(process_md_t),
    EBPF_OFFSET_OF(process_md_t, command_start),
    EBPF_OFFSET_OF(process_md_t, command_end),
    -1,
};

// Need to allocate these in ebpf_structs.h in ebpf-for-windows repo.
#define BPF_PROG_TYPE_PROCESS 99999
#define BPF_ATTACH_TYPE_PROCESS 99999

static const ebpf_program_info_t _ebpf_process_program_info = {
    {"process", &_ebpf_process_context_descriptor, EBPF_PROGRAM_TYPE_PROCESS_GUID, BPF_PROG_TYPE_PROCESS},
    EBPF_COUNT_OF(_process_ebpf_extension_helper_function_prototype),
    _process_ebpf_extension_helper_function_prototype,
};

static const ebpf_program_section_info_t _ebpf_process_section_info[] = {
    {
        L"process",
        &EBPF_PROGRAM_TYPE_PROCESS,
        &EBPF_ATTACH_TYPE_PROCESS,
        BPF_ATTACH_TYPE_PROCESS,
        BPF_ATTACH_TYPE_PROCESS,
    },
};
