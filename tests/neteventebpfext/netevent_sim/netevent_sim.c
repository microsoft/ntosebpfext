// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define NO_CRT
// clang-format off
#include <wdm.h>
#include <wsk.h>
// clang-format on
#include "netevent_npi_client.h"
#include "netevent_npi_provider.h"

#include <guiddef.h>
#include <ntstrsafe.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
KDEFERRED_ROUTINE timer_dpc_routine;

// As defined in \include\ebpf_netevent_hooks.h
#define NOTIFY_EVENT_TYPE_NETEVENT 100

// Function prototypes
static NTSTATUS
_netevent_provider_attach_client(
    _In_ HANDLE NmrBindingHandle,
    _In_ void* provider_context,
    _In_ PNPI_REGISTRATION_INSTANCE ClientRegistrationInstance,
    _In_ void* ClientBindingContext,
    _In_ const void* ClientDispatch,
    _Out_ void** ProviderBindingContext,
    _Out_ const void** ProviderDispatch);
static NTSTATUS
_netevent_provider_detach_client(_In_ HANDLE ProviderBindingContext);
static void
_netevent_provider_cleanup_binding_context(_In_ HANDLE ProviderBindingContext);
void
timer_dpc_routine(
    _In_ struct _KDPC* Dpc,
    _In_opt_ void* DeferredContext,
    _In_opt_ void* SystemArgument1,
    _In_opt_ void* SystemArgument2);

// Globals
static KTIMER _timer;
static KDPC _timer_dpc;
static EX_RUNDOWN_REF _rundown_ref;
volatile LONG _event_counter = 0;
static HANDLE _netevent_provider_handle;
const NETEVENT_NPI_PROVIDER_CHARACTERISTICS _netevent_provider_specific_characteristics = {0};
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
        .NpiSpecificCharacteristics = &_netevent_provider_specific_characteristics // optional
    }};
PROVIDER_REGISTRATION_CONTEXT _netevent_provider_registration_context = {
    .provider_registration_handle = NULL
    // TBD: Add any other provider-specific information here
};
PROVIDER_BINDING_CONTEXT _netevent_provider_binding_context = {
    .client_binding_handle = NULL,
    .client_dispatch = NULL,
    .client_registration_instance = NULL,
    .client_binding_context = NULL};

// Timer DPC routine
void
timer_dpc_routine(
    _In_ struct _KDPC* Dpc,
    _In_opt_ void* DeferredContext,
    _In_opt_ void* SystemArgument1,
    _In_opt_ void* SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // Send the payload to the attached NMR client (if any)
    if (_netevent_provider_binding_context.client_dispatch != NULL) {

        // Acquire the rundown protection
        if (!ExAcquireRundownProtection(&_rundown_ref)) {
            // The driver is unloading, so return without doing anything
            return;
        }

        // Create the test payload
        netevent_event_info_t testPayload;
        char message[200] = {0};
        message[0] = (unsigned char)NOTIFY_EVENT_TYPE_NETEVENT;
        LONG counter = InterlockedIncrement(&_event_counter);
        NTSTATUS status = RtlStringCbPrintfA(
            message + 1, sizeof(message) - 1, "Hello from netevent - dropping packets! (total %ld)", counter);
        if (NT_SUCCESS(status)) {
            testPayload.event_data_start = (unsigned char*)message;
            testPayload.event_data_end = testPayload.event_data_start + strlen(message) + 1;

            // Invoke the client's dispatch routine
            netevent_dispatch_address_table_t* dispatch_table =
                ((NETEVENT_NPI_CLIENT_DISPATCH*)_netevent_provider_binding_context.client_dispatch)->netevent_dispatch;
            netevent_push_event push_event_helper =
                (netevent_push_event)dispatch_table->netevent_ext_helper_functions_t[0];
            push_event_helper(&testPayload);

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
        due_time.QuadPart = -100; // 100 nanoseconds
        KeInitializeTimerEx(&_timer, NotificationTimer);
        KeSetTimerEx(&_timer, due_time, 100, &_timer_dpc);
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

    // Reset the binding context
    _netevent_provider_binding_context.client_binding_handle = NULL;
    _netevent_provider_binding_context.client_registration_instance = NULL;
    _netevent_provider_binding_context.client_binding_context = NULL;
    _netevent_provider_binding_context.client_dispatch = NULL;

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
        &_netevent_provider_characteristics, &_netevent_provider_registration_context, &_netevent_provider_handle);

    return status;
}
