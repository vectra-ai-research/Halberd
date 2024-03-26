'''
Module Name : Discover_One_Drive
Description : Recon users one drive information
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/me/drive/root/children"

    try:
        # recon one drive
        raw_response = graph_get_request(url = endpoint_url)

        if 'error' in raw_response:
            return False, {"Error" : raw_response.get('error').get('message', 'N/A')}, None

        # parse raw response => pretty response
        try:
            # create pretty response
            pretty_response = {}
            for item_info in raw_response:
                pretty_response[item_info['id']] = {
                    'Name' : item_info.get('name', 'N/A'),
                    'Id' : item_info.get('id', 'N/A'),
                    'Web Url' : item_info.get('webUrl', 'N/A'),
                    'Size' : item_info.get('size', 'N/A'),
                    'Created By' : item_info.get('createdBy', 'N/A')
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