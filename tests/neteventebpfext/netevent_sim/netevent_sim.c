// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define NO_CRT
// clang-format off
#include <wdm.h>
#include <wsk.h>
// clang-format on
#include "netevent_npi_client.h"
#include "netevent_npi_provider.h"
#include "netevent_types.h"

#include <guiddef.h>
#include <ntstrsafe.h>

// Registry key path and value name for the event interval
#define EVENT_INTERVAL_KEY_PATH L"\\Registry\\Machine\\Software\\eBPF\\Parameters"
#define EVENT_INTERVAL_VALUE_NAME L"NetEventInterval"
#define DEFAULT_EVENT_INTERVAL 1U // milliseconds
#define DISPATCH_IRQL_EVENT_INTERVAL 2U

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
KDEFERRED_ROUTINE timer_dpc_routine;
LONG g_event_interval = 0;

// Function prototypes
static NTSTATUS
_netevent_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* provider_context,
    _In_ PNPI_REGISTRATION_INSTANCE client_registration_instance,
    _In_ void* client_binding_context,
    _In_ const void* client_dispatch,
    _Out_ void** provider_binding_context,
    _Out_ const void** provider_dispatch);
static NTSTATUS
_netevent_provider_detach_client(_In_ HANDLE provider_binding_context);
static void
_netevent_provider_cleanup_binding_context(_In_ HANDLE provider_binding_context);
void
timer_dpc_routine(
    _In_ struct _KDPC* dpc,
    _In_opt_ void* deferred_context,
    _In_opt_ void* system_argument1,
    _In_opt_ void* system_argument2);

// Globals
static KTIMER _timer;
static KDPC _timer_dpc;
static EX_RUNDOWN_REF _rundown_ref;
volatile LONG _event_counter = 0;
static HANDLE _netevent_provider_handle;
const NPI_PROVIDER_CHARACTERISTICS _netevent_provider_characteristics = {
    .Version = NPI_PROVIDER_CHARACTERISTICS_VERSION,
    .Length = sizeof(NPI_PROVIDER_CHARACTERISTICS),
    .ProviderAttachClient = (PNPI_PROVIDER_ATTACH_CLIENT_FN)_netevent_provider_attach_client,
    .ProviderDetachClient = (PNPI_PROVIDER_DETACH_CLIENT_FN)_netevent_provider_detach_client,
    .ProviderCleanupBindingContext =
        (PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN)_netevent_provider_cleanup_binding_context,
    .ProviderRegistrationInstance = {
        .Version = NPI_CURRENT_CLIENT_REVISION,
        .Size = sizeof(NPI_REGISTRATION_INSTANCE),
        .NpiId = &netevent_npiid,
        .ModuleId = &netevent_module_id,
        .Number = 0,
        .NpiSpecificCharacteristics = &netevent_npi_specific_characteristics}};
PROVIDER_REGISTRATION_CONTEXT _netevent_provider_registration_context = {.provider_registration_handle = NULL};
PROVIDER_BINDING_CONTEXT _netevent_provider_binding_context = {
    .client_binding_handle = NULL,
    .client_dispatch = NULL,
    .client_registration_instance = NULL,
    .client_binding_context = NULL};

// Timer DPC routine
void
timer_dpc_routine(
    _In_ struct _KDPC* dpc,
    _In_opt_ void* deferred_context,
    _In_opt_ void* system_argument1,
    _In_opt_ void* system_argument2)
{
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(deferred_context);
    UNREFERENCED_PARAMETER(system_argument1);
    UNREFERENCED_PARAMETER(system_argument2);

    // Send the payload to the attached NMR client (if any)
    if (_netevent_provider_binding_context.client_dispatch != NULL) {
        // Acquire the rundown protection
        if (!ExAcquireRundownProtection(&_rundown_ref)) {
            // The driver is unloading, so return without doing anything
            return;
        }

        // Create a test event
        LONG counter = InterlockedIncrement(&_event_counter);
        netevent_message_t demo_event = {
            .header =
                {.EventId = NOTIFY_EVENT_TYPE_NETEVENT_LOG,
                 .PacketDescriptor = {.PacketMetaDataLength = sizeof(PKTMON_EVT_STREAM_METADATA)}},
            .payload = {
                .event_id = NOTIFY_EVENT_TYPE_NETEVENT_LOG,
                .source_ip = {192, 168, 1, 1},
                .destination_ip = {10, 11, 12, 1},
                .source_port = 12345,
                .destination_port = 80,
                .event_counter = counter}};

        if (_netevent_provider_binding_context.client_dispatch->capture_type == NeteventCapture_Drop) {
            demo_event.header.EventId = NOTIFY_EVENT_TYPE_NETEVENT_DROP;
            demo_event.header.Metadata.DropReason = DROP_REASON_SECURITY_POLICY;
            demo_event.payload.event_id = NOTIFY_EVENT_TYPE_NETEVENT_DROP;
        }

        // Create the event payload
        netevent_event_info_t event_payload = {
            .event_data_start = (unsigned char*)&demo_event,
            .event_data_end = (unsigned char*)&demo_event + sizeof(demo_event)};

        // Invoke the NPI client's push_event_helper routine
        netevent_push_event push_event_helper =
            (netevent_push_event)(_netevent_provider_binding_context.client_dispatch->helper_function_address[0]);

        if ((counter % DISPATCH_IRQL_EVENT_INTERVAL) == 0) {
            KIRQL old_irql;
            KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
            push_event_helper(&event_payload);
            KeLowerIrql(old_irql);
        } else {
            push_event_helper(&event_payload);
        }

        // Release the rundown protection
        ExReleaseRundownProtection(&_rundown_ref);
    }
}

// Callback function to attach a client to the provider
static NTSTATUS
_netevent_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* provider_context,
    _In_ PNPI_REGISTRATION_INSTANCE client_registration_instance,
    _In_ void* client_binding_context,
    _In_ const void* client_dispatch,
    _Out_ void** provider_binding_context,
    _Out_ const void** provider_dispatch)
{
    UNREFERENCED_PARAMETER(provider_context);

    // Save the client's binding handle and dispatch routines in the provider binding context
    _netevent_provider_binding_context.client_binding_handle = nmr_binding_handle;
    _netevent_provider_binding_context.client_registration_instance = client_registration_instance;
    _netevent_provider_binding_context.client_binding_context = client_binding_context;
    _netevent_provider_binding_context.client_dispatch = client_dispatch;

    // Assign the output values
    if (provider_binding_context != NULL) {
        *provider_binding_context = &_netevent_provider_binding_context;
    }
    if (provider_dispatch != NULL) {
        // This provider does not have any dispatch routines
        *provider_dispatch = NULL;
    }

    // Lastly,start the timer (if it's not already running)
    if (!KeCancelTimer(&_timer)) {
        // Timer is not yet running, so initialize and start it
        LARGE_INTEGER due_time;
        due_time.QuadPart = -g_event_interval;
        KeInitializeTimerEx(&_timer, NotificationTimer);
        KeSetTimerEx(&_timer, due_time, g_event_interval, &_timer_dpc);
    }

    return STATUS_SUCCESS;
}

// Callback function to detach a client from the provider
NTSTATUS
_netevent_provider_detach_client(_In_ HANDLE provider_binding_context)
{
    UNREFERENCED_PARAMETER(provider_binding_context);

    // Stop the timer if it's running
    KeCancelTimer(&_timer);

    return STATUS_SUCCESS;
}

// Callback function to clean up the binding context
void
_netevent_provider_cleanup_binding_context(_In_ HANDLE provider_binding_context)
{
    if (provider_binding_context != NULL) {

        ((PROVIDER_BINDING_CONTEXT*)provider_binding_context)->client_binding_handle = NULL;
        ((PROVIDER_BINDING_CONTEXT*)provider_binding_context)->client_registration_instance = NULL;
        ((PROVIDER_BINDING_CONTEXT*)provider_binding_context)->client_binding_context = NULL;
        ((PROVIDER_BINDING_CONTEXT*)provider_binding_context)->client_dispatch = NULL;
    }
}

NTSTATUS
read_event_interval(
    _In_ PWSTR value_name,
    _In_ ULONG value_type,
    _In_ PVOID value_data,
    _In_ ULONG value_length,
    _Inout_ PVOID context,
    _In_ PVOID entry_context)
{
    UNREFERENCED_PARAMETER(value_name);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(entry_context);

    if (value_type == REG_DWORD && value_length == sizeof(ULONG)) {
        g_event_interval = *(PULONG)value_data;
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_PARAMETER;
}

// Driver unload routine
_Use_decl_annotations_ void
DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // Stop the timer
    KeCancelTimer(&_timer);

    // Wait for the client callbacks to complete
    ExWaitForRundownProtectionRelease(&_rundown_ref);

    // Deregister the provider module from the NMR
    NTSTATUS status = NmrDeregisterProvider(_netevent_provider_handle);
    if (status == STATUS_PENDING) {
        // Wait for the deregistration to be completed
        NmrWaitForProviderDeregisterComplete(_netevent_provider_handle);
    }
}

// Driver entry point
_Use_decl_annotations_ NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    // Define the registry query table, to retrieve the registry value for the event interval
    RTL_QUERY_REGISTRY_TABLE query_table[] = {
        {
            .QueryRoutine = read_event_interval, // Query routine
            .Flags = RTL_QUERY_REGISTRY_DIRECT,  // Flags
            .Name = EVENT_INTERVAL_VALUE_NAME,   // Name
            .EntryContext = &g_event_interval,   // Entry context
            .DefaultType = REG_DWORD,            // Default type
            .DefaultData = &g_event_interval,    // Default data
            .DefaultLength = sizeof(ULONG)       // Default length
        },
        {0} // Terminating null entry
    };
    status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, EVENT_INTERVAL_KEY_PATH, query_table, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        g_event_interval = DEFAULT_EVENT_INTERVAL;
    }

    // Specify the driver unload function
    DriverObject->DriverUnload = DriverUnload;

    // Initialize rundown protection
    ExInitializeRundownProtection(&_rundown_ref);

    // Initialize the timer and assign the DPC routine
    KeInitializeTimer(&_timer);
    KeInitializeThreadedDpc(&_timer_dpc, timer_dpc_routine, NULL);

    // Register the provider with the NMR
    status = NmrRegisterProvider(
        &_netevent_provider_characteristics, &_netevent_provider_registration_context, &_netevent_provider_handle);

    return status;
}
