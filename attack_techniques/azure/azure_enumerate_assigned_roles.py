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
        super().__init__("Enumerate Role Assignment", "Enumerates Azure RBAC role assignments to discover permissions granted to identities (users, groups, service principals) within the target subscription. This technique helps map out the access control landscape by revealing: who has access (users, groups, service principals), what level of access they have (role definitions), where they have access (scope of assignments)", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            principal_type: str = kwargs.get("principal_type", None)
            scope: str = kwargs.get("scope", None)
            principal_id: str = kwargs.get("principal_id", None)

            # Validate principal_type if provided
            valid_principal_types = ["User", "Group", "ServicePrincipal", "Application"]
            if principal_type and principal_type not in valid_principal_types:
                return ExecutionStatus.FAILURE, {
                    "error": f"Invalid principal_type. Must be one of: {', '.join(valid_principal_types)}",
                    "message": "Invalid principal type provided"
                }
            
            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # create client
            mgmt_client = AuthorizationManagementClient(credential, subscription_id)

            # List role assignments with appropriate filter
            if scope:
                role_assignments_list = mgmt_client.role_assignments.list_for_scope(scope=scope)
            else:
                role_assignments_list = mgmt_client.role_assignments.list_for_subscription()

            # Convert to list of dicts and apply filters
            role_assignments = []
            for role_assignment in role_assignments_list:
                assignment_dict = role_assignment.as_dict()
                
                # Apply principal type filter
                if principal_type and assignment_dict.get('principal_type') != principal_type:
                    continue
                
                # Apply principal ID filter
                if principal_id and assignment_dict.get('principal_id') != principal_id:
                    continue
                
                role_assignments.append(assignment_dict)

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully enumerated {len(role_assignments)} role assignments",
                "value": {
                    "filters_applied": {
                        "principal_type": principal_type,
                        "scope": scope,
                        "principal_id": principal_id
                    },
                    "role_assignments": role_assignments
                }
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerated role assignments in target Azure subscription"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "principal_type": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Principal Type (User/Group/ServicePrincipal/Application)",
                "input_field_type": "text"
            },
            "scope": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Scope",
                "input_field_type": "text"
            },
            "principal_id": {
                "type": "str", 
                "required": False,
                "default": None,
                "name": "Principal ID (User/Group ID)",
                "input_field_type": "text"
            }
        }