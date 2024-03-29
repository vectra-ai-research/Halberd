'''
Module Name: Assign_Directory_Role_To_User
Module Description: Assign a directory role to a user account in Entra ID
'''
from core.GraphFunctions import graph_get_request, graph_post_request, graph_check_guid

def TechniqueMain(user_id,role_id):
    
    # input validation
    if user_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if role_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    # get user info
    if graph_check_guid(user_id) == False:
        # get user guid if upn provided in input
        user_string = user_id
        user_endpoint_url = 'https://graph.microsoft.com/v1.0/users'
        params = {
            '$filter': f'userPrincipalName eq \'{user_string}\''
        }

        user_recon_response = graph_get_request(user_endpoint_url, params=params)
        if 'error' in user_recon_response:
            # graph request failed
            return False, {"Error" : user_recon_response.get('error').get('message', 'N/A')}, None
        
        # get user_id and user_upn
        for user in user_recon_response:
            user_id = user['id']
            user_upn = user['userPrincipalName']
    
    else:
        # get additional user info if user id provided in input
        user_endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
        user_recon_response = graph_get_request(user_endpoint_url)
        if 'error' in user_recon_response:
            # graph request failed
            return False, {"Error" : user_recon_response.get('error').get('message', 'N/A')}, None
        
        # get user_id and user_upn
        user_id = user_recon_response['id']
        user_upn = user_recon_response['userPrincipalName']
        
    # get role info
    if graph_check_guid(role_id) == False:
        # get role guid if role name provided in input
        role_string = role_id
        role_endpoint_url = 'https://graph.microsoft.com/v1.0/directoryRoles'
        params = {
            '$filter': f'displayName eq \'{role_string}\''
        }

        role_recon_response = graph_get_request(role_endpoint_url, params=params)
        if 'error' in role_recon_response:
            # graph request failed
            return False, {"Error" : role_recon_response.get('error').get('message', 'N/A')}, None
        
        # get role_id and role_display_name
        for role in role_recon_response:
            role_id = role['id']
            role_template_id = role['roleTemplateId']
            role_display_name = role['displayName']

    else:
        # get additional role info if role id or role template id provided in input
        role_endpoint_url = 'https://graph.microsoft.com/v1.0/directoryRoles'
        params = {
            '$filter': f'roleTemplateId eq \'{role_id}\''
        }

        # attempt recon if input is role id        
        role_recon_response = graph_get_request(role_endpoint_url, params=params)
        if 'error' in role_recon_response:
            # graph request failed
            params = {
                '$filter': f'id eq \'{role_id}\''
            }
            # attempt recon if input is role template id
            role_recon_response = graph_get_request(role_endpoint_url, params=params)
            if 'error' in role_recon_response:
                # graph request failed
                return False, {"Error" : role_recon_response.get('error').get('message', 'N/A')}, None
        
        # get role_id and role_display_name
        for role in role_recon_response:
            role_id = role['id']
            role_template_id = role['roleTemplateId']
            role_display_name = role['displayName']


    # attempt role assignment
    endpoint_url = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'
    
    # construct request payload
    data = {
    "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
    "principalId": user_id,
    "roleDefinitionId": role_id,
    "directoryScopeId": "/"  
    }

    try:
        raw_response = graph_post_request(endpoint_url, data = data)

        # role assignment operation successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    'Message' : "Role assigned",
                    'UPN' : user_upn,
                    'User ID' : user_id,
                    'Role Name' : role_display_name,
                    'Role ID' : role_id,
                    'Role Template ID' : role_template_id
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
        
        # role assignment operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "User ID or UPN", "id" : "user-object-id-text-input", "type" : "text", "placeholder" : "eea797f8-7d94-5015-9977-64babe7d9507", "element_type" : "dcc.Input"},
        {"title" : "Role ID or Name", "id" : "directory-role-id-text-input", "type" : "text", "placeholder" : "05c6930b1-6c88-8024-8844-32babe7d9194", "element_type" : "dcc.Input"}
    ]