'''
Module Name : Discover_Groups
Description : Recon groups present in microsoft tenant
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/groups"
    
    try:
        # recon groups
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
                    'Description' : application_info.get('description', 'N/A'),
                    'Assignable Role' : application_info.get('isAssignableToRole', 'N/A'),
                    'Membership Rule' : application_info.get('membershipRule', 'N/A'),
                    'Security Enabled' : application_info.get('securityEnabled', 'N/A'),
                    'Visibility' : application_info.get('visibility', 'N/A')
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