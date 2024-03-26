'''
Module Name: Assign_Directory_Role_To_User
Module Description: Assign a directory role to a user account in Entra ID
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(user_id,role_id):
    
    # input validation
    if user_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if role_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    endpoint_url = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'
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
                    'Message' : "Role assigned to user",
                    'User' : user_id,
                    'Role' : role_id,
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
        {"title" : "User Object ID", "id" : "user-object-id-text-input", "type" : "text", "placeholder" : "eea797f8-7d94-5015-9977-64babe7d9507", "element_type" : "dcc.Input"},
        {"title" : "Directory Role ID", "id" : "directory-role-id-text-input", "type" : "text", "placeholder" : "05c6930b1-6c88-8024-8844-32babe7d9194", "element_type" : "dcc.Input"}
    ]