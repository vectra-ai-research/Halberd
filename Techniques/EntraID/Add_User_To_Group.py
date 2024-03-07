'''Add User Account to Group'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(user_id, group_id):
    print
    endpoint_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"
    data = {
        "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
    }

    response = graph_post_request(url = endpoint_url, data= data)

    if response.status_code == 204:
        return "Technique Successful : User Added to Group"
    else:
        return f"Technique Failed. Response Code: {response.status_code}"

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "User Object ID", "id" : "user-object-id-text-input", "type" : "text", "placeholder" : "eea797f8-7d94-5015-9977-64babe7d9507", "element_type" : "dcc.Input"},
        {"title" : "Target Group Object ID", "id" : "group-object-id-text-input", "type" : "text", "placeholder" : "05c6930b1-6c88-8024-8844-32babe7d9194", "element_type" : "dcc.Input"}
    ]