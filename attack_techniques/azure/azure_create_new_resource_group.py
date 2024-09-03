from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.resource import ResourceManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureCreateNewResourceGroup(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1578.005",
                technique_name="Modify Cloud Compute Infrastructure",
                tactics=["Defense Evasion"],
                sub_technique_name="Modify Cloud Compute Configurations"
            )
        ]
        super().__init__("Create New Resource Group", "Creates new resource group in the target Azure subscription", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            new_rg_name: str = kwargs["new_rg_name"]
            new_rg_location: str = kwargs["new_rg_location"]

            credential = AzureAccess.get_azure_auth_credential()
            # retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # create client
            resource_client = ResourceManagementClient(credential, subscription_id)

            # resource group object
            rg_object = {
                "location": new_rg_location
            }

            # create resource group
            new_rg = resource_client.resource_groups.create_or_update(
                new_rg_name, rg_object
            )

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully created new resource group {new_rg_name} in Azure",
                "value": {
                    "rg_ame" : new_rg.name,
                    "rg_location" : new_rg.location
                }
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to create new resource group"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "new_rg_name": {"type": "str", "required": True, "default": None, "name": "New Resource Group Location", "input_field_type" : "text"},
            "new_rg_location": {"type": "str", "required": True, "default": None, "name": "New Resource Group Location", "input_field_type" : "text"}
        }