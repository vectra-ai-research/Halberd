from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.compute import ComputeManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureDeployMaliciousExtensionOnVM(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                tactics=["Execution"],
                sub_technique_name=None
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT301.2",
                technique_name="Virtual Machine Scripting",
                tactics=["Execution"],
                sub_technique_name="CustomScriptExtension"
            )
        ]
        super().__init__("VM - Deploy Malicious Extension", "Deploy malicious extensions across all VMs within scale set by exploiting the extension update feature on a Virtual Machine Scale Set (VMSS). This allows to gain unauthorized access, execute arbitrary commands, or install backdoors, potentially compromising the entire VMSS and its operations.", mitre_techniques, azure_trm_technique)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            resource_group_name: str = kwargs["resource_group_name"]
            vmss_name: str = kwargs["vmss_name"]
            az_region: str = kwargs["az_region"]

            # Input validation
            if resource_group_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": {"input_required": "Resource Group Name"},
                    "message": "Invalid Technique Input"
                }

            if vmss_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": {"input_required": "VMSS Name"},
                    "message": "Invalid Technique Input"
                }

            if az_region in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": {"input_required": "Azure Region"},
                    "message": "Invalid Technique Input"
                }

            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # Create client
            compute_client = ComputeManagementClient(credential, subscription_id)

            # Get VMSS and os type
            vmss = compute_client.virtual_machine_scale_sets.get(resource_group_name, vmss_name)
            os_type = vmss.virtual_machine_profile.storage_profile.os_disk.os_type
            
            if os_type == "Windows":
                extension_params = {
                    'location': az_region,
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
                    'location': az_region,
                    'publisher': 'Microsoft.Azure.Extensions',
                    'type': 'VMAccessForLinux',
                    'type_handler_version': '1.5',
                    'auto_upgrade_minor_version': True,
                    'settings': {},
                    'protected_settings': None,
                }
                extension_name = 'VMAccessForLinux'
            else:
                return ExecutionStatus.FAILURE, {
                    "error": f"Unsupported OS type: {os_type}",
                    "message": "Failed to update extension on VMSS"
                }

            response = compute_client.virtual_machine_scale_set_extensions.begin_create_or_update(
                resource_group_name=resource_group_name,
                vm_scale_set_name=vmss_name,
                vmss_extension_name=extension_name,
                extension_parameters=extension_params
            ).result()

            # Return results
            return ExecutionStatus.SUCCESS, {
                "message": f"{extension_name} extension updated successfully on VMSS {vmss_name} running {os_type}",
                "value": {
                    "extension_name" : extension_name.name,
                    "vmss_name" : vmss_name,
                    "os_type" : os_type,
                    "message" : f"{extension_name} extension updated successfully on VMSS {vmss_name} running {os_type}"
                }
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to update extension on VMSS"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "resource_group_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"},
            "vmss_name": {"type": "str", "required": True, "default": None, "name": "VMSS Name", "input_field_type" : "text"},
            "az_region": {"type": "str", "required": True, "default": None, "name": "Azure Region", "input_field_type" : "text"}
        }