'''
Module Name: List_IAM_Roles
Module Description: List all IAM roles or supply path prefix to filter certain roles.
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_roles.html
'''
from core.AWSFunctions import CreateClient

def TechniqueMain(path_prefix = None):

    # initialize boto3 iam client
    my_client = CreateClient('iam')

    try:
        if path_prefix in [None,""]:
            # list all iam roles
            raw_response = my_client.list_roles()
        else:
            # list roles with supplied path prefix
            raw_response = my_client.list_roles(PathPrefix=path_prefix)
        
        try:
            pretty_response = {}
            all_roles = raw_response['Roles']
            for role in all_roles:
                # all_user_output[user['UserId']] = user
                pretty_response[role['RoleId']]= {
                    "Role Name" : role.get('RoleName', 'N/A'),
                    "Role ID" : role.get('RoleId', 'N/A'),
                    "ARN" : role.get('Arn', 'N/A'),
                    "Path" : role.get('Path', 'N/A'),
                    "Max Session Duration" : role.get('MaxSessionDuration', 'N/A')
                }
            return True, raw_response, pretty_response
        except:
            # return only raw response if pretty response fails
            return True, raw_response, None

    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Role Path Prefix (optional)", "id" : "role-path-prefix-text-input", "type" : "text", "placeholder" : "/app_xyz/comp_123", "element_type" : "dcc.Input"},
    ]