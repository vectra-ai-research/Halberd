from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.resource import ResourceManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureEnumerateResourceGroups(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Resource Groups", "Enumerates resource groups in the target Azure subscription", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            # Get credentials
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # Create client
            resource_client = ResourceManagementClient(credential, subscription_id)
            
            # List resource groups
            groups_list = resource_client.resource_groups.list()

            resource_groups = [group_list_object.name for group_list_object in groups_list]

            if resource_groups:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(resource_groups)} Azure resource groups",
                    "value": resource_groups
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No resource groups found in Azure subscription - {subscription_id}",
                    "value": []
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate resource groups in Azure subscription"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "subscription_id": {"type": "str", "required": False, "default": None, "name": "Subscription ID", "input_field_type" : "text"}
        }