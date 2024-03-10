'''
Module Name: List_IAM_Roles.py
Description: List all IAM roles or supply path prefix to filter certain roles.
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_roles.html
'''
from core.AWSFunctions import CreateClient

def TechniqueMain(path_prefix = None):

    # initialize boto3 iam client
    my_client = CreateClient('iam')

    try:
        # list all iam roles
        if path_prefix in [None,""]:
            response = my_client.list_roles()
        # list roles with supplied path prefix
        else:
            response = my_client.list_roles( PathPrefix=path_prefix)
        
        all_roles = response['Roles']

    except Exception as e:
        return f"Failed to list roles: {e}"

    # create response display
    role_info = {}

    for role in all_roles:
        role_info[role['RoleName']] = {
            "Role Name" : role.get('RoleName', 'N/A'),
            "Role ID" : role.get('RoleId', 'N/A'),
            "ARN" : role.get('MaxSessionDuration', 'N/A'),
            "Path" : role.get('Path', 'N/A'),
            "Max Session Duration" : role.get('MaxSessionDuration', 'N/A')
        }
    
    return role_info

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Role Path Prefix (optional)", "id" : "role-path-prefix-text-input", "type" : "text", "placeholder" : "/app_xyz/comp_123", "element_type" : "dcc.Input"},
    ]