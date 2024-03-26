'''
Module Name : Discover_Conditional_Access_Policies
Description : Recon conditional access policies in microsoft tenant
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

    try:
        # recon cap
        raw_response = graph_get_request(url = endpoint_url)
    
        if 'error' in raw_response:
            return False, {"Error" : raw_response.get('error').get('message', 'N/A')}, None

        # parse raw response => pretty response
        try:
            pretty_response = {}

            for cap_info in raw_response:
                pretty_response[cap_info['id']] = {
                    'Display Name' : cap_info.get('displayName', 'N/A'),
                    'Id' : cap_info.get('id', 'N/A'),
                    'Description' : cap_info.get('description', 'N/A'),
                    'State' : cap_info.get('state', 'N/A'),
                    'Conditions' : cap_info.get('conditions', 'N/A'),
                    'Grant Controls' : cap_info.get('grantControls', 'N/A'),
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