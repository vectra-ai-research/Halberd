'''
Module Name : Discover_Applications
Description : Recon applications available in microsoft tenant
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/applications/"

    try:
        # recon applications
        raw_response = graph_get_request(url = endpoint_url)

        if 'error' in raw_response:
            return False, {"Error" : raw_response.get('error').get('message', 'N/A')}, None

        # parse raw response => pretty response
        try:
            # create pretty response
            pretty_response = {}
            for application_info in raw_response:
                pretty_response[application_info['id']] = {
                    'Display Name' : application_info.get('displayName', 'N/A'),
                    'Id' : application_info.get('id', 'N/A'),
                    'App Id' : application_info.get('appId', 'N/A'),
                    'Description' : application_info.get('description', 'N/A'),
                    'App Roles' : application_info.get('appRoles', 'N/A'),
                    'Password Credentials' : application_info.get('passwordCredentials', 'N/A'),
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