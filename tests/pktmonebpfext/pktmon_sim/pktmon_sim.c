// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang-format off
#include <wdm.h>
#include <wsk.h>
// clang-format on
#include <guiddef.h>
#include <ntstrsafe.h>

// Define the GUID for the PktMon NPI
NPIID PKTMON_NPI_ID = {0xcd3d4424, 0x657e, 0x404c, {0x87, 0xb2, 0xac, 0xf9, 0x28, 0x2c, 0xdd, 0x82}};

// Define the NPI
#define NPI_CURRENT_CLIENT_REVISION 1
#define NPI_PROVIDER_CHARACTERISTICS_VERSION 1
typedef struct
{
    unsigned char* event_data; ///< Data associated with the event.
    size_t event_data_length;  ///< Length of the event data.
} pktmon_event_info_t;

// Define the NMR Provider context
typedef struct _NMR_PROVIDER_CONTEXT
{
    HANDLE provider_handle; // Variable to contain the handle for the registration
    NPI_PROVIDER_CHARACTERISTICS provider_characteristics;

} NMR_PROVIDER_CONTEXT, *PNMR_PROVIDER_CONTEXT;

// Define the NPI client dispatch structure
typedef struct _NPI_CLIENT_DISPATCH
{
    VOID (*pktmon_push_event)(HANDLE, pktmon_event_info_t, size_t);
} NPI_CLIENT_DISPATCH, *PNPI_CLIENT_DISPATCH;

// Define the provider binding context
typedef struct PROVIDER_BINDING_CONTEXT_
{
    HANDLE client_binding_handle;                            // Handle of the attached client
    CONST NPI_CLIENT_DISPATCH* client_dispatch;              // Dispatch routines of the attached client
    PNPI_REGISTRATION_INSTANCE client_registration_instance; // Registration instance of the attached client
    PVOID client_binding_context;                            // Binding context of the attached client
} PROVIDER_BINDING_CONTEXT, *PPROVIDER_BINDING_CONTEXT;

// Globals
KTIMER g_timer;
KDPC g_dpc;
static NMR_PROVIDER_CONTEXT g_provider_context;
static PROVIDER_BINDING_CONTEXT g_provider_binding_context;
EX_RUNDOWN_REF g_rundown_ref;
volatile LONG g_payload_counter = 0;
NPI_REGISTRATION_INSTANCE npi_registration_instance = {
    NPI_CURRENT_CLIENT_REVISION,       // Version
    sizeof(NPI_REGISTRATION_INSTANCE), // Size
    &PKTMON_NPI_ID,                    // NpiId
    NULL,                              // ModuleId
    0,                                 // Number
    NULL                               // NpiSpecificCharacteristics
};

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
    if (g_provider_binding_context.client_dispatch != NULL) {

        // Acquire the rundown protection
        if (!ExAcquireRundownProtection(&g_rundown_ref)) {
            // The driver is unloading, so return without doing anything
            return;
        }

        // Create the test payload
        pktmon_event_info_t testPayload;
        char message[200] = {0};
        LONG counter = InterlockedIncrement(&g_payload_counter);
        NTSTATUS status =
            RtlStringCbPrintfA(message, sizeof(message), "Hello from pktmon - dropping packets! (total %ld)", counter);
        if (NT_SUCCESS(status)) {
            testPayload.event_data = (unsigned char*)message;
            testPayload.event_data_length = sizeof(testPayload.event_data);

            // Invoke the client's dispatch routine
            g_provider_binding_context.client_dispatch->pktmon_push_event(
                g_provider_binding_context.client_binding_context, testPayload, sizeof(testPayload));
            // DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "%s\n", message);
        } else {
            // Failed to format the message
            InterlockedDecrement(&g_payload_counter);
            DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "Failed to format the message: 0x%X\n", status);
        }

        // Release the rundown protection
        ExReleaseRundownProtection(&g_rundown_ref);
    }
}

// Callback function to attach a client to the provider
static NTSTATUS
provider_attach_client_callback(
    _In_ HANDLE NmrBindingHandle,
    _In_ PVOID provider_context,
    _In_ PNPI_REGISTRATION_INSTANCE ClientRegistrationInstance,
    _In_ PVOID ClientBindingContext,
    _In_ CONST VOID* ClientDispatch,
    _Out_ PVOID* ProviderBindingContext,
    _Out_ CONST VOID** ProviderDispatch)
{
    UNREFERENCED_PARAMETER(provider_context);

    // Save the client's binding handle and dispatch routines in the provider context
    g_provider_binding_context.client_binding_handle = NmrBindingHandle;
    g_provider_binding_context.client_registration_instance = ClientRegistrationInstance;
    g_provider_binding_context.client_binding_context = ClientBindingContext;
    g_provider_binding_context.client_dispatch = ClientDispatch;

    // Start the timer only if it's not already running
    if (!KeCancelTimer(&g_timer)) {
        // Timer is not already running, so initialize and start it
        LARGE_INTEGER dueTime;
        dueTime.QuadPart = -100; // 100 nanoseconds
        KeInitializeTimerEx(&g_timer, NotificationTimer);
        KeSetTimerEx(&g_timer, dueTime, 100, &g_dpc);
    }

    // Return success
    *ProviderBindingContext = NULL;
    *ProviderDispatch = NULL;

    return STATUS_SUCCESS;
}

// Callback function to detach a client from the provider
NTSTATUS
provider_detach_client_callback(_In_ HANDLE ProviderBindingContext)
{
    UNREFERENCED_PARAMETER(ProviderBindingContext);

    // Stop the timer if it's running
    KeCancelTimer(&g_timer);

    return STATUS_SUCCESS;
}

// Callback function to clean up the binding context
VOID
provider_cleanup_binding_context_callback(_In_ HANDLE ProviderBindingContext)
{
    UNREFERENCED_PARAMETER(ProviderBindingContext);
}

// Driver unload routine
VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // Stop the timer
    KeCancelTimer(&g_timer);

    // Wait for the client callbacks to complete
    ExWaitForRundownProtectionRelease(&g_rundown_ref);

    // Deregister the provider module from the NMR
    NTSTATUS status = NmrDeregisterProvider(g_provider_context.provider_handle);
    if (status == STATUS_PENDING) {
        // Wait for the deregistration to be completed
        NmrWaitForProviderDeregisterComplete(g_provider_context.provider_handle);
    } else {
        // Handle error
    }
}

// Driver entry point
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    // Specify the driver unload function
    DriverObject->DriverUnload = DriverUnload;

    // Define the provider characteristics
    RtlZeroMemory(&g_provider_context, sizeof(NMR_PROVIDER_CONTEXT));
    g_provider_context.provider_characteristics.Version = NPI_PROVIDER_CHARACTERISTICS_VERSION;
    g_provider_context.provider_characteristics.Length = sizeof(NPI_PROVIDER_CHARACTERISTICS);
    g_provider_context.provider_characteristics.ProviderAttachClient = provider_attach_client_callback;
    g_provider_context.provider_characteristics.ProviderDetachClient = provider_detach_client_callback;
    g_provider_context.provider_characteristics.ProviderCleanupBindingContext =
        provider_cleanup_binding_context_callback;
    g_provider_context.provider_characteristics.ProviderRegistrationInstance = npi_registration_instance;

    // Initialize rundown protection
    ExInitializeRundownProtection(&g_rundown_ref);

    // Initialize the timer and assign the DPC routine
    KeInitializeTimer(&g_timer);
    KeInitializeDpc(&g_dpc, timer_dpc_routine, NULL);

    // Register the provider with the NMR
    status = NmrRegisterProvider(
        &g_provider_context.provider_characteristics, &g_provider_context, &g_provider_context.provider_handle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}
