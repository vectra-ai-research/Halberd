from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
import re
from typing import Dict, Any, Tuple
from azure.mgmt.authorization import AuthorizationManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureRemoveRoleAssignment(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1531",
                technique_name="Account Access Removal",
                tactics=["Impact"],
                sub_technique_name=None
            )
        ]
        super().__init__("Remove Role Assignment", "Uassigning a role from an entity to prevent access to a subscription or resource group", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            principal_id: str = kwargs['principal_id']
            role_name: str = kwargs['role_name']
            scope_level: str = kwargs['scope_level']
            scope_rg_name: str = kwargs.get('scope_rg_name', None)
            scope_resource_name: str = kwargs.get('scope_resource_name', None)

            # Input validation
            if principal_id in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Asignee GUID"}
                }
            
            if role_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Role Name"}
                }
            
            if scope_level in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Role Name"}
                }

            # set scope level
            if scope_level in ["", None, "root", "/"]:
                # Get tenant_id
                tenant_id = AzureAccess().get_current_subscription_info().get('tenantId')
                scope = f"providers/Microsoft.Management/managementGroups/{tenant_id}"
                # scope = "/"
            elif scope_level == "subscription":
                # retrieve current subscription id
                current_sub_info = AzureAccess().get_current_subscription_info()
                subscription_id = current_sub_info.get("id")
                scope = f"/subscriptions/{subscription_id}/"
            elif scope_level == "rg":
                # retrieve subscription id
                current_sub_info = AzureAccess().get_current_subscription_info()
                subscription_id = current_sub_info.get("id")
                scope = f"/subscriptions/{subscription_id}/resourceGroups/{scope_rg_name}"
            elif scope_level == "resource":
                # input validation
                if scope_rg_name in ["", None]:
                    return ExecutionStatus.FAILURE, {
                        "error": {"Incorect Value" : "Resource Group Name"},
                        "message": "For scope level = resource, Resource Group Name is required"
                    }
                if scope_resource_name in ["", None]:
                    return ExecutionStatus.FAILURE, {
                        "error": {"Incorect Value" : "Resource Name"},
                        "message": "For scope level = resource, Resource Name is required"
                    }
                else:
                    pattern = r"^\w+/\w+/\w+$"
                    if re.match(pattern, scope_resource_name):
                        # retrieve subscription id
                        current_sub_info = AzureAccess().get_current_subscription_info()
                        subscription_id = current_sub_info.get("id")
                        
                        # scope_resource expected format "resource_provider/resource_type/resource_name"
                        scope = f"/subscriptions/{subscription_id}/resourceGroups/{scope_rg_name}/providers/{scope_resource_name}"
                        
                    else:
                        return ExecutionStatus.FAILURE, {
                            "error": {"Incorect Value" : "Resource Name"},
                            "message": "Invalid Resource Name"
                        }
            else:
                # handle invalid scope_level inputs
                return ExecutionStatus.FAILURE, {
                    "error": {"Scope Level" : "Incorrect Value"},
                    "message": "Incorrect scope level"
                }

            # Get credentials
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            # Create client
            auth_mgmt_client = AuthorizationManagementClient(credential, subscription_id)

            # Get all role definitions
            role_definitions = auth_mgmt_client.role_definitions.list(scope)
            # Search for the role by name to get role id
            for role in role_definitions:
                if role.role_name.lower() == role_name.lower():
                    role_id = role.id

            # Get role assignments for the scope
            role_assignments = auth_mgmt_client.role_assignments.list_for_scope(scope)

            # Find and delete the specific role assignment
            for assignment in role_assignments:
                if (assignment.principal_id == principal_id and assignment.role_definition_id == role_id):
                    auth_mgmt_client.role_assignments.delete_by_id(assignment.id)

                    result = {
                        "role_removed" : True,
                        "assignment_id" : assignment.id,
                        'scope' : scope,
                        "principal_id" : assignment.principal_id,
                        "principal_type" : assignment.principal_type
                    }
                    return ExecutionStatus.SUCCESS, {
                        "message": f"Successfully removed role",
                        "value": result
                    }
        
            return ExecutionStatus.FAILURE, {
                "error": "Failed to find role assignment",
                "message": "Failed to find role assignment"
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to remove role assignment"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "principal_id": {"type": "str", "required": True, "default": None, "name": "Target GUID [User ID / Group ID / App ID]", "input_field_type" : "text"},
            "role_name": {"type": "str", "required": True, "default": None, "name": "Role Name", "input_field_type" : "text"},
            "scope_level": {"type": "str", "required": True, "default":None, "name": "Scope : Level", "input_field_type" : "text"},
            "scope_rg_name": {"type": "str", "required": False, "default": None, "name": "Scope : Resource Group Name", "input_field_type" : "text"},
            "scope_resource_name": {"type": "str", "required": False, "default": None, "name": "Scope : Resource Name", "input_field_type" : "text"},
        }