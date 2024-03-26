'''
Module Name : Discover_Directory_Roles
Description : Recon directory roles in the tenant
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/directoryRoles"

    try:
        # recon directory roles
        raw_response = graph_get_request(url = endpoint_url)

        if 'error' in raw_response:
            return False, {"Error" : raw_response.get('error').get('message', 'N/A')}, None

        # parse raw response => pretty response
        try:
            # create pretty response
            pretty_response = {}
            for role_info in raw_response:
                pretty_response[role_info['id']] = {
                    'Display Name' : role_info.get('displayName', 'N/A'),
                    'Description' : role_info.get('description', 'N/A'),
                    'Role Template Id' : role_info.get('roleTemplateId', 'N/A'),
                    'Id' : role_info.get('id', 'N/A')
                }
            return True, raw_response, pretty_response
        except:
            # return only raw response if pretty response fails
            return True, raw_response, None
        
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return []