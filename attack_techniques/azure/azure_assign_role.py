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
            principal_id: str = kwargs['asignee_guid']
            principal_type: str = kwargs.get('principal_type', 'User')
            azure_role_id: str = kwargs['azure_role_id']
            scope_level: str = kwargs['scope_level']
            scope_rg_name: str = kwargs.get('scope_rg_name', None)
            scope_resource_name: str = kwargs.get('scope_resource_name', None)

            # set scope level
            if scope_level in ["", None, "root", "/"]:
                scope = "/"
            else:
                if scope_level == "subscription":
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
                        return False, {"Error" : "Invalid 'Resource Grouop Name' Input"}, None
                    if scope_resource_name in ["", None]:
                        return False, {"Error" : "Invalid Technique Input"}, None
                    else:
                        pattern = r"^\w+/\w+/\w+$"
                        if re.match(pattern, scope_resource_name):
                            # retrieve subscription id
                            current_sub_info = AzureAccess().get_current_subscription_info()
                            subscription_id = current_sub_info.get("id")
                            
                            # scope_resource expected format "resource_provider/resource_type/resource_name"
                            scope = f"/subscriptions/{subscription_id}/resourceGroups/{scope_rg_name}/providers/{scope_resource_name}"
                        else:
                            return False, {"Error" : "Invalid 'Resource Name' Input"}, None
                else:
                    # handle invalid scope_level inputs
                    return False, {"Error" : {"Scope Level" : "Incorrect Value", "Valid Inputs" : "'root', 'subscription', 'rg', 'resource'"}}, None


            credential = AzureAccess.get_azure_auth_credential()
            # create client
            auth_mgmt_client = AuthorizationManagementClient(credential, subscription_id)

            # create the role assignment
            role_definition = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{azure_role_id}"

            role_assignment_properties = {
                "properties": {
                    "roleDefinitionId": role_definition, 
                    "principalId": principal_id, 
                    "principalType": {principal_type}
                }
            }

            # create unique uuid for role assignment name
            role_assignment_name = str(uuid.uuid4())

            # attempt role assignment
            role_assignment_result = auth_mgmt_client.role_assignments.create(scope = scope, role_assignment_name = role_assignment_name, parameters = role_assignment_properties)

            try:
                if role_assignment_result:
                    result = {
                        "Role Definition ID" : role_assignment_result.role_definition_id,
                        "Principal ID" : role_assignment_result.principal_id,
                        "Princiapl Type" : role_assignment_result.principal_type,
                        "Description" : role_assignment_result.description,
                        "Condition" : role_assignment_result.condition
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
                "message": "Failed to enumerate Azure compute VMs"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "principal_id": {"type": "str", "required": True, "name": "Asignee GUID [User ID / Group ID / App ID]", "input_field_type" : "text"},
            "principal_type": {"type": "str", "required": False, "default":"User", "name": "Principal Type", "input_field_type" : "text"},
            "azure_role_id": {"type": "str", "required": True, "name": "Azure Role ID", "input_field_type" : "text"},
            "scope_level": {"type": "str", "required": True, "default":"/", "name": "Scope : Level", "input_field_type" : "text"},
            "scope_rg_name": {"type": "str", "required": False, "default": None, "name": "Scope : Resource Group Name", "input_field_type" : "text"},
            "scope_resource_name": {"type": "str", "required": False, "default": None, "name": "Scope : Resource Name", "input_field_type" : "text"},
        }