#Discover User Accounts
from core.GraphFunctions import graph_get_request

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/users/"

    tenant_users = graph_get_request(url = endpoint_url)
    
    return tenant_users


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return []