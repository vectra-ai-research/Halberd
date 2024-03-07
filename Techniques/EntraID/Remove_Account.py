'''Delete User Account'''
from core.GraphFunctions import graph_delete_request

def TechniqueMain(user_id):
    endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"

    delete_user_response = graph_delete_request(url = endpoint_url)
    print(delete_user_response)

    return delete_user_response

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Account UPN", "id" : "remove-account-access-text-input", "type" : "text", "placeholder" : "user@domain.com", "element_type" : "dcc.Input"}
    ]