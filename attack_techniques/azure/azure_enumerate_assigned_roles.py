from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.authorization import AuthorizationManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureEnumerateRoleAssignment(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1069",
                technique_name="Permission Groups Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Role Assignment", "Enumerates role assignments in target Azure subscription", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # create client
            mgmt_client = AuthorizationManagementClient(credential, subscription_id)

            # list role assignments
            role_assignments = mgmt_client.role_assignments.list_for_subscription()

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully enumerated role assignments",
                "value": role_assignments
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerated role assignments in target Azure subscription"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}