'''
Module Name : Discover_Directory_Roles.py
Description : Recon directory roles in the tenant
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/directoryRoles"

    try:
        # request to list directory roles
        response = graph_get_request(url = endpoint_url)
        
    except Exception as e:
        return e

    # create response output to display 
    output_response = {}
    for role in response:
        output_response[role['displayName']] = role

    return output_response


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return []