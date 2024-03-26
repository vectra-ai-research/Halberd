'''
Module Name : Discover_SP_Sites
Description : Recon sharepoint sites
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/sites"
    
    try:
        # recon sp sites
        raw_response = graph_get_request(url = endpoint_url)

        if 'error' in raw_response:
            return False, {"Error" : raw_response.get('error').get('message', 'N/A')}, None

        # parse raw response => pretty response
        try:
            # create pretty response
            pretty_response = {}
            for sp_site_info in raw_response:
                pretty_response[sp_site_info['id']] = {
                    'Display Name' : sp_site_info.get('displayName', 'N/A'),
                    'Web Url' : sp_site_info.get('webUrl', 'N/A'),
                    'Personal Site' : sp_site_info.get('isPersonalSite', 'N/A'),
                    'Site Collection' : sp_site_info.get('siteCollection', 'N/A'),
                    'Root' : sp_site_info.get('root', 'N/A'),
                    'Id' : sp_site_info.get('id', 'N/A'),
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