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
        super().__init__("Enumerate Resources", "Enumerates resources in the target Azure subscription", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            credential = AzureAccess.get_azure_auth_credential()
            # retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # create client
            resource_client = ResourceManagementClient(credential, subscription_id)
            
            # list resource groups
            groups_list = resource_client.resource_groups.list()
            group_list = []

            resources = [group_list_object.name for group_list_object in groups_list]

            if resources:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(resources)} Azure resources",
                    "value": resources
                }
            else:
                return ExecutionStatus.PARTIAL_SUCCESS, {
                    "message": f"No resources found in Azure subscription - {subscription_id}",
                    "value": []
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate resources in Azure subscription"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "subscription_id": {"type": "str", "required": False, "default": None, "name": "Subscription ID", "input_field_type" : "text"}
        }