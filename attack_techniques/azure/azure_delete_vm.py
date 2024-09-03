from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.compute import ComputeManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureDeleteVm(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1499",
                technique_name="Endpoint Denial of Service",
                tactics=["Impact"],
                sub_technique_name=None
            )
        ]
        super().__init__("Delete VM", "Deletes virtual machines in the target Azure subscription", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            vm_name: str = kwargs["vm_name"]
            rg_name: str = kwargs["rg_name"]

            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # create client
            compute_client = ComputeManagementClient(credential, subscription_id)
            
            # attremp delete vm request
            vm_delete = compute_client.virtual_machines.delete(rg_name, vm_name)

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully deleted VM - {vm_name} in Azure resource group - {rg_name}",
                "value": {
                    "vm_name" : vm_name,
                    "resource_group" : rg_name,
                    "Status" : "Deleted"
                }
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to delete VM in target Azure resource group"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "vm_name": {"type": "str", "required": True, "default": None, "name": "VM Name", "input_field_type" : "text"},
            "rg_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"},
        }