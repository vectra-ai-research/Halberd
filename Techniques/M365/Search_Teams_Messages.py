'''
Module Name : Search_Teams_Messages
Description : Recon teams messages using a search keyword
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(search_term):
    endpoint_url = "https://graph.microsoft.com/v1.0/search/query"
    
    data = {
        "requests":[
            {
                "entityTypes" : [
                    "chatMessage"
                    ],
                "query": {
                    "queryString": search_term
                },
                "from": 0,
                "size": 25,
            }
        ]
    }

    try:
        raw_response = graph_post_request(url = endpoint_url, data = data)

        # teams messages search operation successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    raw_response
                }
                return True, raw_response.json(), pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response.json(), None
        
        # teams messages search operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Search Keyword", "id" : "teams-search-keyword-text-input", "type" : "text", "placeholder" : "secrets", "element_type" : "dcc.Input"}
    ]