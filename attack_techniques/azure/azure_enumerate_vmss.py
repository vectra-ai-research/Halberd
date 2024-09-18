from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.compute import ComputeManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureEnumerateVMSS(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Virtual Machine Scale Set", "Enumerates virtual machine scale set (VMSS) in Azure", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            rg_name: str = kwargs["rg_name"]
            
            # Input Validation
            if rg_name in [None,""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"input_required" : "Resource Group name"},
                    "message": "Invalid Technique Input"
                }

            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # Create client
            compute_client = ComputeManagementClient(credential, subscription_id)
            
            # List resources
            vmss_list = compute_client.virtual_machine_scale_sets.list(
                resource_group_name = rg_name
            )
            print(vmss_list)

            vmss = [vmss_object for vmss_object in vmss_list]

            if vmss:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(vmss)} Azure VMSS",
                    "value": vmss
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No VMSS found in resource group - {rg_name}",
                    "value": []
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate VMSS in resource group"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "rg_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"}
        }