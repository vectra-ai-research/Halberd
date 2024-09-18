from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.resource import ResourceManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureEnumerateResources(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Resources", "Enumerates resources in a target Azure resource group", mitre_techniques)

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
            resource_client = ResourceManagementClient(credential, subscription_id)
            
            # List resources
            resources_list = resource_client.resources.list_by_resource_group(rg_name)

            resources = [resource_list_object for resource_list_object in resources_list]

            if resources:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(resources)} Azure resources",
                    "value": resources
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No resources found in resource group - {rg_name}",
                    "value": []
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate resources in resource group"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "rg_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"}
        }