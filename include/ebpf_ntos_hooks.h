// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>

// This file contains APIs for hooks and helpers that are
// exposed by ntosebpfext.sys for use by eBPF programs.

#define TOKEN_SID_MAX_SIZE 68 ///< Maximum size of a SID (SECURITY_MAX_SID_SIZE).

typedef enum _process_operation
{
    PROCESS_OPERATION_CREATE, ///< Process creation.
    PROCESS_OPERATION_DELETE, ///< Process deletion.
} process_operation_t;

typedef struct _process_md
{
    uint8_t* command_start;            ///< Pointer to start of the command line as UTF-16 string.
    uint8_t* command_end;              ///< Pointer to end of the command line as UTF-16 string.
    uint64_t process_id;               ///< Process ID.
    uint64_t parent_process_id;        ///< Parent process ID.
    uint64_t creating_process_id;      ///< Creating process ID.
    uint64_t creating_thread_id;       ///< Creating thread ID.
    uint64_t creation_time;            ///< Process creation time (as a FILETIME).
    uint64_t exit_time;                ///< Process exit time (as a FILETIME).  Set only for PROCESS_OPERATION_DELETE.
    uint32_t process_exit_code;        ///< Process exit status.  Set only for PROCESS_OPERATION_DELETE.
    process_operation_t operation : 8; ///< Operation to do.
    uint32_t token_sid_size;           ///< Size of the token SID in bytes. Set only for PROCESS_OPERATION_CREATE.
    uint8_t token_sid[TOKEN_SID_MAX_SIZE]; ///< Primary token SID. Set only for PROCESS_OPERATION_CREATE.
} process_md_t;

/*
 * @brief Handle process creation and deletion.
 *
 * Program type: \ref EBPF_PROGRAM_TYPE_PROCESS
 *
 * Attach type(s):
 * \ref EBPF_ATTACH_TYPE_PROCESS
 *
 * @param[in] context \ref process_md_t
 * @return STATUS_SUCCESS to permit the operation, or a failure NTSTATUS value to deny the operation.
 * Value of STATUS_SUCCESS is 0x0.
 * For PROCESS_OPERATION_DELETE operation, the return value is ignored.
 */
typedef int
process_hook_t(process_md_t* context);

// Process helper functions.
#define PROCESS_EXT_HELPER_FN_BASE 0xFFFF

#if !defined(__doxygen) && !defined(EBPF_HELPER)
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
#endif

typedef enum
{
    BPF_FUNC_process_get_image_path = PROCESS_EXT_HELPER_FN_BASE + 1,
    BPF_FUNC_process_get_account_name = PROCESS_EXT_HELPER_FN_BASE + 2,
    BPF_FUNC_process_get_account_domain = PROCESS_EXT_HELPER_FN_BASE + 3,
} ebpf_process_helper_id_t;

/**
 * @brief Get the image path of the process.
 *
 * @param[in] context Process metadata.
 * @param[out] path Buffer to store the image path.
 * @param[in] path_length Length of the buffer.
 *
 * @retval >=0 The length of the image path.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_process_get_image_path, (process_md_t * ctx, uint8_t* path, uint32_t path_length));
#ifndef __doxygen
#define bpf_process_get_image_path ((bpf_process_get_image_path_t)BPF_FUNC_process_get_image_path)
#endif

/**
 * @brief Get the account name associated with the process's primary token.
 *
 * @param[in] context Process metadata.
 * @param[out] name Buffer to store the account name.
 * @param[in] name_length Length of the buffer in bytes.
 *
 * @retval >=0 The length of the account name in bytes.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_process_get_account_name, (process_md_t * ctx, uint8_t* name, uint32_t name_length));
#ifndef __doxygen
#define bpf_process_get_account_name ((bpf_process_get_account_name_t)BPF_FUNC_process_get_account_name)
#endif

/**
 * @brief Get the account domain associated with the process's primary token.
 *
 * @param[in] context Process metadata.
 * @param[out] domain Buffer to store the account domain.
 * @param[in] domain_length Length of the buffer in bytes.
 *
 * @retval >=0 The length of the account domain in bytes.
 * @retval <0 A failure occurred.
 */
EBPF_HELPER(int, bpf_process_get_account_domain, (process_md_t * ctx, uint8_t* domain, uint32_t domain_length));
#ifndef __doxygen
#define bpf_process_get_account_domain ((bpf_process_get_account_domain_t)BPF_FUNC_process_get_account_domain)
#endif
