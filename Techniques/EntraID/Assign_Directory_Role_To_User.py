'''Assign Role to User'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(user_id,role_id):
    endpoint_url = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'
    data = {
    "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
    "principalId": user_id,
    "roleDefinitionId": role_id,
    "directoryScopeId": "/"  
    }
    role_assignment = graph_post_request(endpoint_url, data = data)
    return role_assignment


def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "User Object ID", "id" : "user-object-id-text-input", "type" : "text", "placeholder" : "eea797f8-7d94-5015-9977-64babe7d9507", "element_type" : "dcc.Input"},
        {"title" : "Directory Role ID", "id" : "directory-role-id-text-input", "type" : "text", "placeholder" : "05c6930b1-6c88-8024-8844-32babe7d9194", "element_type" : "dcc.Input"}
    ]