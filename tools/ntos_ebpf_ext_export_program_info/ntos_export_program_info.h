// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_program_types.h"

void
print_help(_In_z_ const char* file_name);

uint32_t
export_all_program_information();

uint32_t
export_all_section_information();

uint32_t
clear_ebpf_store();
