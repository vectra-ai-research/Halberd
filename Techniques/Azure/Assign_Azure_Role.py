'''
Module Name :Assign_Azure_Role
Module Description : Attempts to assign an azure role to a user, group or service principal. 
'''

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from core.AzureFunctions import GetCurrentSubscriptionAccessInfo
import uuid
import re

def TechniqueMain(principal_id, principal_type, role_definition_id, scope_level, scope_rg_name, scope_resource):
    try:
        # input validation
        if principal_id in ["", None]:
            return False, {"Error" : "Asignee GUID Input"}, None
        
        if role_definition_id in ["", None]:
            return False, {"Error" : {"Role ID" : "Input Required", "Reference" : "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"}}, None
        
        if principal_type in ["", None]:
            principal_type = "User"
        elif principal_type in ["User", "Group", "Service Principal"]:
            pass
        else:
            # handle invalid principal_type inputs
            return False, {"Error" : {"Principal Type" : "Incorrect Value", "Valid Inputs" : "'User', 'Group', 'Service Principal'"}}, None

    
        # set scope level
        if scope_level in ["", None, "root", "/"]:
            scope = "/"
        else:
            if scope_level == "subscription":
                # retrieve current subscription id
                current_sub_info = GetCurrentSubscriptionAccessInfo()
                subscription_id = current_sub_info.get("id")
                scope = f"/subscriptions/{subscription_id}/"
            elif scope_level == "rg":
                # retrieve subscription id
                current_sub_info = GetCurrentSubscriptionAccessInfo()
                subscription_id = current_sub_info.get("id")
                scope = f"/subscriptions/{subscription_id}/resourceGroups/{scope_rg_name}"
            elif scope_level == "resource":
                # input validation
                if scope_rg_name in ["", None]:
                    return False, {"Error" : "Invalid 'Resource Grouop Name' Input"}, None
                if scope_resource in ["", None]:
                    return False, {"Error" : "Invalid Technique Input"}, None
                else:
                    pattern = r"^\w+/\w+/\w+$"
                    if re.match(pattern, scope_resource):
                        # retrieve subscription id
                        current_sub_info = GetCurrentSubscriptionAccessInfo()
                        subscription_id = current_sub_info.get("id")
                        
                        # scope_resource expected format "resource_provider/resource_type/resource_name"
                        scope = f"/subscriptions/{subscription_id}/resourceGroups/{scope_rg_name}/providers/{scope_resource}"
                    else:
                        return False, {"Error" : "Invalid 'Resource Name' Input"}, None
            else:
                # handle invalid scope_level inputs
                return False, {"Error" : {"Scope Level" : "Incorrect Value", "Valid Inputs" : "'root', 'subscription', 'rg', 'resource'"}}, None

        # create credential object
        default_credential = DefaultAzureCredential()

        # create client
        auth_mgmt_client = AuthorizationManagementClient(default_credential, subscription_id)

        # create the role assignment
        role_definition = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_definition_id}"

        role_assignment_properties = {
            "properties": {
                "roleDefinitionId": role_definition, 
                "principalId": principal_id, 
                "principalType": "User"
            }
        }

        # create unique uuid for role assignment name
        role_assignment_name = str(uuid.uuid4())

        # attempt role assignment
        role_assignment_result = auth_mgmt_client.role_assignments.create(scope = scope, role_assignment_name = role_assignment_name, parameters = role_assignment_properties)

        try:
            # create pretty response
            pretty_response = {}
            pretty_response["Success"] = {
                "Role Definition ID" : role_assignment_result.role_definition_id,
                "Principal ID" : role_assignment_result.principal_id,
                "Princiapl Type" : role_assignment_result.principal_type,
                "Description" : role_assignment_result.description,
                "Condition" : role_assignment_result.condition
            }
            return True, role_assignment_result, pretty_response
        except:
            # return raw response if pretty response fails
            return True, role_assignment_result, None
    
    except Exception as e:
        return False, {"Error" : e}, None
    
def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Asignee GUID [User ID / Group ID / App ID]", "id" : "principal-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Principal Type [Values - User / Group / ServicePrincipal]", "id" : "principal-type-text-input", "type" : "text", "placeholder" : "Default : User", "element_type" : "dcc.Input"},
        {"title" : "Azure Role ID", "id" : "role-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Scope : Level (Optional) [Values - root, subscription, rg]", "id" : "scope-level-text-input", "type" : "text", "placeholder" : "Default : / (Root)", "element_type" : "dcc.Input"},
        {"title" : "Scope: Resource Group Name (Optional)", "id" : "scope-rg-text-input", "type" : "text", "placeholder" : "rg-1x1", "element_type" : "dcc.Input"},
        {"title" : "Scope : Resource Name (Format - resource_provider/resource_type/resource_name)", "id" : "scope-resource-text-input", "type" : "text", "placeholder" : "rp/rt/rn", "element_type" : "dcc.Input"}
    ]
