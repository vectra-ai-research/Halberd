'''
Module Name : Discover_User_Accounts
Description : Recon user accounts present in Entra ID
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/users/"
    
    try:
        # recon user accounts
        raw_response = graph_get_request(url = endpoint_url)

        if 'error' in raw_response:
            return False, {"Error" : raw_response.get('error').get('message', 'N/A')}, None

        # parse raw response => pretty response
        try:
            # create pretty response
            pretty_response = {}
            for user_info in raw_response:
                pretty_response[user_info['id']] = {
                    'Display Name' : user_info.get('displayName', 'N/A'),
                    'UPN' : user_info.get('userPrincipalName', 'N/A'),
                    'Mail' : user_info.get('mail', 'N/A'),
                    'Job Title' : user_info.get('jobTitle', 'N/A'),
                    'Mobile Phone' : user_info.get('mobilePhone', 'N/A'),
                    'Office Location' : user_info.get('officeLocation', 'N/A'),
                    'Id' : user_info.get('id', 'N/A'),
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