'''
Module Name: VMss_Update_SSH_Extension
Module Description: Update the SSH extension on a Virtual Machine Scale Set (VMSS) to enable SSH access, with OS-based checks.
'''

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.core.exceptions import HttpResponseError
from core.AzureFunctions import GetAzureAuthCredential, GetCurrentSubscriptionAccessInfo

def TechniqueMain(subscription_id, resource_group_name, vmss_name, location):

    if resource_group_name in ["", None]:
        return False, {"Error": "Invalid input: Resource Group Name required"}, None
    if vmss_name in ["", None]:
        return False, {"Error": "Invalid input: VMSS Name required"}, None
    if location in ["", None]:
        return False, {"Error": "Invalid input: Location required"}, None

    if subscription_id in ["", None]:
        current_sub_info = GetCurrentSubscriptionAccessInfo()
        subscription_id = current_sub_info.get("id")

    try:
        credential = GetAzureAuthCredential()
        compute_client = ComputeManagementClient(credential, subscription_id)

        vmss = compute_client.virtual_machine_scale_sets.get(resource_group_name, vmss_name)
        os_type = vmss.virtual_machine_profile.storage_profile.os_disk.os_type

        if os_type == "Windows":
            extension_params = {
                'location': location,
                'publisher': 'Microsoft.Azure.OpenSSH',
                'type': 'WindowsOpenSSH',
                'type_handler_version': '3.0',
                'auto_upgrade_minor_version': True,
                'settings': {},
                'protected_settings': None,
            }
            extension_name = 'OpenSSH'
        elif os_type == "Linux":
            extension_params = {
                'location': location,
                'publisher': 'Microsoft.Azure.Extensions',
                'type': 'VMAccessForLinux',
                'type_handler_version': '1.5',
                'auto_upgrade_minor_version': True,
                'settings': {},
                'protected_settings': None,
            }
            extension_name = 'VMAccessForLinux'
        else:
            return False, {"Error": f"Unsupported OS type: {os_type}"}, None

        response = compute_client.virtual_machine_scale_set_extensions.begin_create_or_update(
            resource_group_name=resource_group_name,
            vm_scale_set_name=vmss_name,
            vmss_extension_name=extension_name,
            extension_parameters=extension_params
        ).result()

        pretty_response = {
            "Success": {
                "message": f"{extension_name} extension updated successfully on VMSS {vmss_name} running {os_type}",
            }
        }
        return True, response, pretty_response

    except HttpResponseError as e:
        return False, {"Error": f"HttpResponseError: {e}"}, None
    except Exception as e:
        return False, {"Error": f"Unexpected error: {e}"}, None

def TechniqueInputSrc() -> list:
    return [
        {
            "title": "Subscription ID (Optional)",
            "id": "subscription-id-text-input",
            "type": "text",
            "placeholder": "1234-5678-9098-7654-3210",
            "element_type": "dcc.Input"
        },
        {
            "title": "Resource Group Name",
            "id": "resource-group-name",
            "type": "text",
            "placeholder": "example-vmss-resource-group",
            "element_type": "dcc.Input"
        },
        {
            "title": "VMSS Name",
            "id": "vmss-name",
            "type": "text",
            "placeholder": "example-vmss-name",
            "element_type": "dcc.Input"
        },
        {
            "title": "Location",
            "id": "location",
            "type": "text",
            "placeholder": "eastus",
            "element_type": "dcc.Input"
        }
    ]
