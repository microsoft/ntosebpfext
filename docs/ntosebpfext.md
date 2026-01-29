# NTOS eBPF Extension (ntosebpfext)

## Introduction

This extension provides a way to monitor and control process creation and deletion events in the Windows kernel using eBPF. The extension is built on top of [eBPF for Windows](https://github.com/microsoft/ebpf-for-windows), following the [eBPF Extensions](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/eBpfExtensions.md) model, and leverages the library files from this repository.

The ntosebpfext extension hooks into the Windows kernel's process notification mechanism using `PsSetCreateProcessNotifyRoutineEx`, allowing eBPF programs to observe and potentially influence process lifecycle events.

## Getting Started

### Prerequisites

- eBPF for Windows must be installed. Please follow the instructions in the [eBPF for Windows - Getting started](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/GettingStarted.md) guide to install the eBPF for Windows components on a test-enabled Windows machine/VM.

### Building & Testing the extension

After cloning the repository, make sure to initialize the submodules by running the following command from the root of the repository:

```powershell
.\scripts\initialize_repo.ps1
```

Then, build the `ntosebpfext.sln` solution from the root of the repository, by running the following command:

```cmd
msbuild ntosebpfext.sln /p:Configuration=Debug /p:Platform=x64
```

For this extension, the following artifacts will be generated in the `x64\Debug` (in this case) directory:

- `ntos_ebpf_ext_export_program_info.exe` - A user-mode cmdlet that exports the eBPF program information to the eBPF store.
- `ntosebpfext.sys` - The driver that loads the eBPF program and attaches it to the process lifecycle events.
- `process_monitor.sys` - The native eBPF program that will be invoked by the `ntosebpfext` extension upon process events, which stores them in ring buffer and LRU hash maps.
- `ntosebpfext_unit.exe` - An end-to-end unit test that validates the extension functionality.

#### Testing

To run the end-to-end unit test, you can use the `ntosebpfext_unit.exe` application as follows:

```cmd
REM Required only if the eBPF program information is not exported yet
ntos_ebpf_ext_export_program_info.exe

REM Run the test with debugging enabled
ntosebpfext_unit.exe -d yes
```

This test will perform the following steps:

1. Export the eBPF program info to the eBPF store (located in System's registry, under `HKLM\Software\eBPF`).
1. Load & start the `ntosebpfext.sys` driver.
1. Load and attach the `process_monitor.sys` eBPF program.
1. Simulate process creation and deletion events.
1. Verify that the eBPF program receives the correct context information.
1. Stop and unload all the drivers.

For full end-to-end testing with the user-mode application, see the [process_monitor.Tests](../tests/process_monitor.Tests) project which validates the extension functionality using MSTest.

## Installing the extension

Once the artifacts are generated, to deploy the extension you need to:

- Export the eBPF program to the system's eBPF store using the `ntos_ebpf_ext_export_program_info.exe` application:

    ```cmd
    REM Mainly, to clear-out any previous eBPF program information related to this program type.
    ntos_ebpf_ext_export_program_info.exe --clear
    ntos_ebpf_ext_export_program_info.exe
    ```

- Load and start the `ntosebpfext.sys` eBPF extension driver which will enable loading eBPF programs of type `process` and attaching them to the process lifecycle events:

    ```cmd
    sc create ntosebpfext type=kernel start=demand binPath=ntosebpfext.sys
    sc start ntosebpfext
    ```

## Development

### Writing an eBPF Program that Attaches to the `ntosebpfext` Extension

The simplest way to write an eBPF program that attaches to the process events is to review the `process_monitor.c` eBPF program provided in the `\tools\process_monitor_bpf` project. This program stores process events in a ring buffer and maintains LRU hash maps for process image paths and command lines.

The extension provides the following structure for process events, defined in `include\ebpf_ntos_hooks.h`:

```c
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
    uint64_t exit_time;                ///< Process exit time (as a FILETIME). Set only for PROCESS_OPERATION_DELETE.
    uint32_t process_exit_code;        ///< Process exit status. Set only for PROCESS_OPERATION_DELETE.
    process_operation_t operation : 8; ///< Operation to do.
} process_md_t;
```

To write your own eBPF program, you must create your own project (similar to the `process_monitor_bpf` project) and define a section of type `process` in your eBPF program. The `process` section is used by the `ntosebpfext` extension to attach the eBPF program to the process lifecycle events.

```c
#include "bpf_helpers.h"
#include "ebpf_ntos_hooks.h" // For the process_md_t and process_hook_t definitions.

// Define any eBPF maps that you need here
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// The following line is optional, but is used to verify
// that the ProcessHandler prototype is correct or the compiler
// would complain when the function is actually defined below.
process_hook_t ProcessHandler;

// Define the eBPF program that will be attached to the process events.
SEC("process")
int
ProcessHandler(process_md_t* ctx)
{
    // Your eBPF program logic here
    // Access process information from ctx

    // For example, log to a ring buffer
    bpf_ringbuf_output(&events, ctx, sizeof(*ctx), 0);

    // Return STATUS_SUCCESS (0) to permit the operation
    // Return a failure NTSTATUS value to deny the operation
    // Note: For PROCESS_OPERATION_DELETE, the return value is ignored
    return 0;
}
```

The extension supports attaching multiple eBPF programs, to which process events will be dispatched.

### Helper Functions

The `ntosebpfext` extension provides a custom helper function:

#### `bpf_process_get_image_path`

```c
int bpf_process_get_image_path(process_md_t* ctx, uint8_t* path, uint32_t path_length);
```

**Description:** Retrieves the full image path of the process.

**Parameters:**
- `ctx` - Process metadata context
- `path` - Buffer to store the image path (UTF-16 encoded)
- `path_length` - Length of the buffer in bytes

**Returns:**
- `>= 0` - The length of the image path in bytes
- `< 0` - A failure occurred

**Example usage:**

```c
SEC("process")
int
ProcessHandler(process_md_t* ctx)
{
    char image_path[1024];
    
    // Get the image path
    int len = bpf_process_get_image_path(ctx, (uint8_t*)image_path, sizeof(image_path) - 1);
    if (len > 0) {
        // Image path retrieved successfully
        // Process the image path...
    }
    
    return 0;
}
```

### Process Context Information

The `process_md_t` structure provides comprehensive information about process events:

- **Process Identifiers:**
  - `process_id` - The process ID of the process being created or deleted
  - `parent_process_id` - The parent process ID
  - `creating_process_id` - The process ID that is creating this process
  - `creating_thread_id` - The thread ID that is creating this process

- **Command Line:**
  - `command_start` / `command_end` - Pointers to the command line as a UTF-16 string. The command line can be extracted by reading the memory between these pointers.

- **Timing Information:**
  - `creation_time` - Process creation time as a FILETIME value
  - `exit_time` - Process exit time as a FILETIME value (only valid for `PROCESS_OPERATION_DELETE`)

- **Exit Information:**
  - `process_exit_code` - The process exit code (only valid for `PROCESS_OPERATION_DELETE`)

- **Operation Type:**
  - `operation` - Either `PROCESS_OPERATION_CREATE` or `PROCESS_OPERATION_DELETE`

### Return Values

eBPF programs attached to the `process` hook can influence process creation:

- **For `PROCESS_OPERATION_CREATE` events:**
  - Return `STATUS_SUCCESS` (0) to permit the process creation
  - Return a failure NTSTATUS value (e.g., `STATUS_ACCESS_DENIED = 0xC0000022`) to deny the process creation

- **For `PROCESS_OPERATION_DELETE` events:**
  - The return value is ignored (process deletion cannot be prevented)

### Example: Process Monitor

The `process_monitor` example in `tools\process_monitor_bpf` demonstrates a complete implementation that:

1. Captures process creation and deletion events
2. Stores event metadata in a ring buffer for user-mode consumption
3. Maintains LRU hash maps with process image paths and command lines
4. Uses per-CPU scratch space for efficient string handling

The corresponding user-mode application in `tools\process_monitor` reads events from the ring buffer and displays them in real-time with structured logging.

## Architecture

The ntosebpfext extension uses the Windows kernel's `PsSetCreateProcessNotifyRoutineEx` API to register for process creation and deletion notifications. When a process event occurs:

1. The Windows kernel invokes the extension's notification callback
2. The extension constructs a `process_md_t` context with all relevant information
3. The context is passed to all attached eBPF programs
4. For creation events, if any eBPF program returns a failure status, the process creation is denied
5. For deletion events, the eBPF programs are notified but cannot prevent the deletion

### Extension Components

- **Program Info Provider** - Registers the `process` program type with eBPF for Windows
- **Hook Provider** - Manages the attachment of eBPF programs to process events
- **Context Creation/Destruction** - Handles the lifecycle of the `process_md_t` context
- **Helper Functions** - Provides the `bpf_process_get_image_path` helper

## Use Cases

The ntosebpfext extension enables various security and monitoring scenarios:

- **Process Monitoring** - Real-time tracking of all process creation and deletion events
- **Security Policy Enforcement** - Blocking specific processes based on image path, command line, or other attributes
- **Auditing and Compliance** - Logging process lifecycle events for compliance requirements
- **Behavioral Analysis** - Analyzing process creation patterns for anomaly detection
- **Parental Controls** - Restricting which applications can be launched

## GUIDs and Constants

**Program Type GUID:**
```
EBPF_PROGRAM_TYPE_PROCESS = {0x22ea7b37, 0x1043, 0x4d0d, {0xb6, 0x0d, 0xca, 0xfa, 0x1c, 0x7b, 0x63, 0x8e}}
```

**Attach Type GUID:**
```
EBPF_ATTACH_TYPE_PROCESS = {0x66e20687, 0x9805, 0x4458, {0xa0, 0xdb, 0x38, 0xe2, 0x20, 0xd3, 0x16, 0x85}}
```

**BPF Program Type:**
```
BPF_PROG_TYPE_PROCESS
```

**BPF Attach Type:**
```
BPF_ATTACH_TYPE_PROCESS
```

## Troubleshooting

### Extension fails to load

Ensure that:
- eBPF for Windows is installed and running
- The system is in test mode (bcdedit /set testsigning on)
- The driver is properly signed (or test signing is enabled)
- You have administrator privileges

### eBPF program fails to attach

- Verify that the program type information has been exported using `ntos_ebpf_ext_export_program_info.exe`
- Check that the ntosebpfext.sys driver is loaded and started
- Ensure your eBPF program uses `SEC("process")` and the correct context type

### Process events are not captured

- Verify that the eBPF program is successfully attached
- Check that the program logic is correct and doesn't fail early
- Ensure map definitions are correct and maps are accessible from user mode
- Enable debug logging with the `-d yes` flag when running test applications

## Additional Resources

- [eBPF for Windows Documentation](https://github.com/microsoft/ebpf-for-windows/tree/main/docs)
- [eBPF Extensions Guide](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/eBpfExtensions.md)
- [Windows Process Notify Routines](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [Contributing Guide](../CONTRIBUTING.md)
