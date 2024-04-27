// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ntos_ebpf_ext_helper.h"

DEVICE_OBJECT* _ntos_ebpf_ext_driver_device_object;

_ntosebpf_ext_helper::_ntosebpf_ext_helper() : _ntosebpf_ext_helper(nullptr, nullptr, nullptr) {}

_ntosebpf_ext_helper::_ntosebpf_ext_helper(
    _In_opt_ const void* npi_specific_characteristics,
    _In_opt_ _ebpf_extension_dispatch_function dispatch_function,
    _In_opt_ ntosebpfext_helper_base_client_context_t* client_context)
{
    // Do not use REQUIRE() in this constructor or the destructor will never be called
    // to clean up any state allocated before the REQUIRE.

    if (!NT_SUCCESS(ebpf_ext_trace_initiate())) {
        return;
    }
    trace_initiated = true;

    if (!NT_SUCCESS(ebpf_ext_register_providers())) {
        return;
    }

    provider_registered = true;

    nmr_program_info_client_handle = std::make_unique<nmr_client_registration_t>(&program_info_client, this);

    this->hook_invoke_function = dispatch_function;
    if (dispatch_function != nullptr && client_context != nullptr) {
        hook_client.ClientRegistrationInstance.NpiSpecificCharacteristics = npi_specific_characteristics;
        client_context->helper = this;
        nmr_hook_client_handle = std::make_unique<nmr_client_registration_t>(&hook_client, client_context);
    }
}

_ntosebpf_ext_helper::~_ntosebpf_ext_helper()
{
    if (nmr_hook_client_handle) {
        nmr_hook_client_handle.reset(nullptr);
    }

    if (nmr_program_info_client_handle) {
        nmr_program_info_client_handle.reset(nullptr);
    }

    if (provider_registered) {
        ebpf_ext_unregister_providers();
    }

    if (trace_initiated) {
        ebpf_ext_trace_terminate();
    }
}

std::vector<GUID>
_ntosebpf_ext_helper::program_info_provider_guids()
{
    std::vector<GUID> guids;
    for (const auto& [id, provider] : program_info_providers) {
        guids.push_back(id);
    }
    return guids;
}

ebpf_extension_data_t
_ntosebpf_ext_helper::get_program_info_provider_data(_In_ const GUID& program_info_provider)
{
    auto iter = program_info_providers.find(program_info_provider);

    // We might not find the provider if some allocation failed during initialization.
    REQUIRE(iter != program_info_providers.end());

    return *iter->second->provider_data;
}

NTSTATUS
_ntosebpf_ext_helper::_program_info_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _Inout_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    auto& helper = *reinterpret_cast<_ntosebpf_ext_helper*>(client_context);
    auto client_binding_context = std::make_unique<program_info_provider_t>();
    client_binding_context->module_id = *provider_registration_instance->ModuleId;
    client_binding_context->parent = &helper;
    client_binding_context->provider_data =
        reinterpret_cast<const ebpf_extension_data_t*>(provider_registration_instance->NpiSpecificCharacteristics);

    NTSTATUS status = NmrClientAttachProvider(
        nmr_binding_handle,
        client_binding_context.get(),
        &client_binding_context,
        &client_binding_context->context,
        &client_binding_context->dispatch);

    if (NT_SUCCESS(status)) {
        helper.program_info_providers[provider_registration_instance->ModuleId->Guid].reset(
            client_binding_context.release());
    }
    return status;
}

NTSTATUS
_ntosebpf_ext_helper::_program_info_client_detach_provider(_Inout_ void* client_binding_context)
{
    UNREFERENCED_PARAMETER(client_binding_context);
    return STATUS_SUCCESS;
}

void
_ntosebpf_ext_helper::_program_info_client_cleanup_binding_context(_In_ _Post_invalid_ void* client_binding_context)
{
    UNREFERENCED_PARAMETER(client_binding_context);
}

NTSTATUS
_ntosebpf_ext_helper::_hook_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _Inout_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    UNREFERENCED_PARAMETER(provider_registration_instance);
    const void* provider_dispatch_table;
    auto base_client_context = reinterpret_cast<ntosebpfext_helper_base_client_context_t*>(client_context);
    if (base_client_context == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    const ebpf_extension_dispatch_table_t client_dispatch_table = {
        .version = 1, .count = 1, .function = base_client_context->helper->hook_invoke_function};
    auto provider_characteristics =
        (const ebpf_extension_data_t*)provider_registration_instance->NpiSpecificCharacteristics;
    auto provider_data = (const ebpf_attach_provider_data_t*)provider_characteristics->data;
    if (base_client_context->desired_attach_type != BPF_ATTACH_TYPE_UNSPEC &&
        provider_data->bpf_attach_type != base_client_context->desired_attach_type) {
        return STATUS_ACCESS_DENIED;
    }

    return NmrClientAttachProvider(
        nmr_binding_handle,
        client_context, // Client binding context.
        &client_dispatch_table,
        &base_client_context->provider_binding_context,
        &provider_dispatch_table);
}

NTSTATUS
_ntosebpf_ext_helper::_hook_client_detach_provider(_Inout_ void* client_binding_context)
{
    UNREFERENCED_PARAMETER(client_binding_context);

    // All callbacks we implement are done.
    return STATUS_SUCCESS;
}

void
_ntosebpf_ext_helper::_hook_client_cleanup_binding_context(_In_ void* client_binding_context)
{
    UNREFERENCED_PARAMETER(client_binding_context);
}
