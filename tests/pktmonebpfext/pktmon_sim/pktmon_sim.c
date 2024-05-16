// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define NO_CRT
// clang-format off
#include <wdm.h>
#include <wsk.h>
// clang-format on
#include "pktmon_npi_client.h"
#include "pktmon_npi_provider.h"

#include <guiddef.h>
#include <ntstrsafe.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
KDEFERRED_ROUTINE timer_dpc_routine;

// As defined in \include\ebpf_pktmon_hooks.h
#define NOTIFY_EVENT_TYPE_PKTMON 100

// Function prototypes
static NTSTATUS
_pktmon_provider_attach_client(
    _In_ HANDLE NmrBindingHandle,
    _In_ PVOID provider_context,
    _In_ PNPI_REGISTRATION_INSTANCE ClientRegistrationInstance,
    _In_ PVOID ClientBindingContext,
    _In_ CONST VOID* ClientDispatch,
    _Out_ PVOID* ProviderBindingContext,
    _Out_ CONST VOID** ProviderDispatch);
static NTSTATUS
_pktmon_provider_detach_client(_In_ HANDLE ProviderBindingContext);
static VOID
_pktmon_provider_cleanup_binding_context(_In_ HANDLE ProviderBindingContext);
VOID
timer_dpc_routine(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2);

// Globals
static KTIMER _timer;
static KDPC _timer_dpc;
static EX_RUNDOWN_REF _rundown_ref;
volatile LONG _event_counter = 0;
static HANDLE _pktmon_provider_handle;
const PKTMON_NPI_PROVIDER_CHARACTERISTICS _pktmon_provider_specific_characteristics = {0};
const NPI_PROVIDER_CHARACTERISTICS _pktmon_provider_characteristics = {
    .Version = NPI_PROVIDER_CHARACTERISTICS_VERSION,
    .Length = sizeof(NPI_PROVIDER_CHARACTERISTICS),
    .ProviderAttachClient = (PNPI_PROVIDER_ATTACH_CLIENT_FN)_pktmon_provider_attach_client,
    .ProviderDetachClient = (PNPI_PROVIDER_DETACH_CLIENT_FN)_pktmon_provider_detach_client,
    .ProviderCleanupBindingContext = (PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN)_pktmon_provider_cleanup_binding_context,
    .ProviderRegistrationInstance = {
        .Version = NPI_CURRENT_CLIENT_REVISION,
        .Size = sizeof(NPI_REGISTRATION_INSTANCE),
        .NpiId = &pktmon_npiid,
        .ModuleId = &pktmon_module_id,
        .Number = 0,
        .NpiSpecificCharacteristics = &_pktmon_provider_specific_characteristics // optional
    }};
PROVIDER_REGISTRATION_CONTEXT _pktmon_provider_registration_context = {
    .provider_registration_handle = NULL
    // TBD: Add any other provider-specific information here
};
PROVIDER_BINDING_CONTEXT _pktmon_provider_binding_context = {
    .client_binding_handle = NULL,
    .client_dispatch = NULL,
    .client_registration_instance = NULL,
    .client_binding_context = NULL};

// Timer DPC routine
VOID
timer_dpc_routine(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // Send the payload to the attached NMR client (if any)
    if (_pktmon_provider_binding_context.client_dispatch != NULL) {

        // Acquire the rundown protection
        if (!ExAcquireRundownProtection(&_rundown_ref)) {
            // The driver is unloading, so return without doing anything
            return;
        }

        // Create the test payload
        pktmon_event_info_t testPayload;
        char message[200] = {0};
        message[0] = (unsigned char)NOTIFY_EVENT_TYPE_PKTMON;
        LONG counter = InterlockedIncrement(&_event_counter);
        NTSTATUS status = RtlStringCbPrintfA(
            message + 1, sizeof(message) - 1, "Hello from pktmon - dropping packets! (total %ld)", counter);
        if (NT_SUCCESS(status)) {
            testPayload.event_data_start = (unsigned char*)message;
            testPayload.event_data_end = testPayload.event_data_start + strlen(message) + 1; // TBV dealloc

            // Invoke the client's dispatch routine
            _pktmon_provider_binding_context.client_dispatch->pktmon_push_event(
                _pktmon_provider_binding_context.client_binding_context, testPayload, sizeof(testPayload));
            // DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "%s\n", message);
        } else {
            // Failed to format the message
            InterlockedDecrement(&_event_counter);
            DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "Failed to format the message: 0x%X\n", status);
        }

        // Release the rundown protection
        ExReleaseRundownProtection(&_rundown_ref);
    }
}

// Callback function to attach a client to the provider
static NTSTATUS
_pktmon_provider_attach_client(
    _In_ HANDLE nmr_binding_handle,
    _In_ PVOID provider_context,
    _In_ PNPI_REGISTRATION_INSTANCE client_registration_instance,
    _In_ PVOID client_binding_context,
    _In_ CONST VOID* client_dispatch,
    _Out_ PVOID* provider_binding_context,
    _Out_ CONST VOID** provider_dispatch)
{
    UNREFERENCED_PARAMETER(provider_context);

    // Save the client's binding handle and dispatch routines in the provider context
    _pktmon_provider_binding_context.client_binding_handle = nmr_binding_handle;
    _pktmon_provider_binding_context.client_registration_instance = client_registration_instance;
    _pktmon_provider_binding_context.client_binding_context = client_binding_context;
    _pktmon_provider_binding_context.client_dispatch = client_dispatch;

    // Start the timer only if it's not already running
    if (!KeCancelTimer(&_timer)) {
        // Timer is not yet running, so initialize and start it
        LARGE_INTEGER due_time;
        due_time.QuadPart = -100; // 100 nanoseconds
        KeInitializeTimerEx(&_timer, NotificationTimer);
        KeSetTimerEx(&_timer, due_time, 100, &_timer_dpc);
    }

    // Return success
    if (provider_binding_context != NULL) {
        *provider_binding_context = &_pktmon_provider_binding_context;
    }
    if (provider_dispatch != NULL) {
        *provider_dispatch = NULL; // This provider does not have any dispatch routines
    }

    return STATUS_SUCCESS;
}

// Callback function to detach a client from the provider
NTSTATUS
_pktmon_provider_detach_client(_In_ HANDLE provider_binding_context)
{
    UNREFERENCED_PARAMETER(provider_binding_context);

    // Stop the timer if it's running
    KeCancelTimer(&_timer);

    return STATUS_SUCCESS;
}

// Callback function to clean up the binding context
VOID
_pktmon_provider_cleanup_binding_context(_In_ HANDLE provider_binding_context)
{
    UNREFERENCED_PARAMETER(provider_binding_context);
}

// Driver unload routine
_Use_decl_annotations_ VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // Stop the timer
    KeCancelTimer(&_timer);

    // Wait for the client callbacks to complete
    ExWaitForRundownProtectionRelease(&_rundown_ref);

    // Deregister the provider module from the NMR
    NTSTATUS status = NmrDeregisterProvider(_pktmon_provider_handle);
    if (status == STATUS_PENDING) {
        // Wait for the deregistration to be completed
        NmrWaitForProviderDeregisterComplete(_pktmon_provider_handle);
    } else {
        // Handle error
    }
}

// Driver entry point
_Use_decl_annotations_ NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    // Specify the driver unload function
    DriverObject->DriverUnload = DriverUnload;

    // Initialize rundown protection
    ExInitializeRundownProtection(&_rundown_ref);

    // Initialize the timer and assign the DPC routine
    KeInitializeTimer(&_timer);
    KeInitializeDpc(&_timer_dpc, timer_dpc_routine, NULL);

    // Register the provider with the NMR
    status = NmrRegisterProvider(
        &_pktmon_provider_characteristics, &_pktmon_provider_registration_context, &_pktmon_provider_handle);

    return status;
}
