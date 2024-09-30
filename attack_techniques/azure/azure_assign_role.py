from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
import uuid
import re
from typing import Dict, Any, Tuple
from azure.mgmt.authorization import AuthorizationManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureAssignRole(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.003",
                technique_name="Account Manipulation",
                tactics=["Persistence", "Privilege Escalation"],
                sub_technique_name="Additional Cloud Roles"
            )
        ]
        super().__init__("Assign Role", "Escalate privileges by assigning an Azure role", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            principal_id: str = kwargs['principal_id']
            principal_type: str = kwargs.get('principal_type', 'User')
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
            
            if principal_type in ["", None]:
                principal_type == "User" # Defaults to user
            
            # Retrieve current subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")

            # Set scope level
            if scope_level in ["", None, "root", "/"]:
                scope = "/"
            elif scope_level == "subscription":
                scope = f"/subscriptions/{subscription_id}/"
            elif scope_level == "rg":
                scope = f"/subscriptions/{subscription_id}/resourceGroups/{scope_rg_name}"
            elif scope_level == "resource":
                # Input validation
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
                        # scope_resource expected format "resource_provider/resource_type/resource_name"
                        scope = f"/subscriptions/{subscription_id}/resourceGroups/{scope_rg_name}/providers/{scope_resource_name}"
                        
                    else:
                        return ExecutionStatus.FAILURE, {
                            "error": {"Incorect Value" : "Resource Name"},
                            "message": "Invalid Resource Name"
                        }
            else:
                # Handle invalid scope_level inputs
                return ExecutionStatus.FAILURE, {
                    "error": {"Scope Level" : "Incorrect Value"},
                    "message": "Incorrect scope level"
                }

            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Create client
            auth_mgmt_client = AuthorizationManagementClient(credential, subscription_id)
            
            # Get all role definitions
            role_definitions = auth_mgmt_client.role_definitions.list(scope)
            # Search for the role by name to get role id
            for role in role_definitions:
                if role.role_name.lower() == role_name.lower():
                    role_definition = role.id
                    role_description = role.description

            # Create the role assignment
            role_assignment_properties = {
                "properties": {
                    "roleDefinitionId": role_definition, 
                    "principalId": principal_id, 
                    "principalType": principal_type
                }
            }

            # Create unique uuid for role assignment name
            role_assignment_name = str(uuid.uuid4())

            # Attempt role assignment
            role_assignment_result = auth_mgmt_client.role_assignments.create(scope = scope, role_assignment_name = role_assignment_name, parameters = role_assignment_properties)

            try:
                if role_assignment_result:
                    result = {
                        "role_assigned" : True,
                        "role_definition_id" : role_assignment_result.role_definition_id,
                        "principal_id" : role_assignment_result.principal_id,
                        "princiapl_type" : role_assignment_result.principal_type,
                        "role_description" : role_description
                    }
                    return ExecutionStatus.SUCCESS, {
                        "message": f"Successfully assigned role",
                        "value": result
                    }
            except Exception as e:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": "Failed to assign role"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to assign role"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "principal_id": {"type": "str", "required": True, "default": None, "name": "Target GUID [User ID / Group ID / App ID]", "input_field_type" : "text"},
            "principal_type": {"type": "str", "required": False, "default":"User", "name": "Principal Type", "input_field_type" : "text"},
            "role_name": {"type": "str", "required": True, "default": None, "name": "Role Name", "input_field_type" : "text"},
            "scope_level": {"type": "str", "required": True, "default":"/", "name": "Scope : Level", "input_field_type" : "text"},
            "scope_rg_name": {"type": "str", "required": False, "default": None, "name": "Scope : Resource Group Name", "input_field_type" : "text"},
            "scope_resource_name": {"type": "str", "required": False, "default": None, "name": "Scope : Resource Name", "input_field_type" : "text"},
        }