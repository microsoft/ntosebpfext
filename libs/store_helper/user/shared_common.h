// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_extension.h"
#include "ebpf_program_types.h"

bool
ebpf_validate_helper_function_prototype_array(
    _In_reads_(count) const ebpf_helper_function_prototype_t* helper_prototype, uint32_t count);

bool
ebpf_validate_program_section_info(_In_ const ebpf_program_section_info_t* section_info);

bool
ebpf_validate_program_info(_In_ const ebpf_program_info_t* program_info);
