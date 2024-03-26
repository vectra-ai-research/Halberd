'''
Module Name : Search_User_SP_One_Drive
Description : Recon user one drive to find files using search keyword
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(search_term):
    #https://learn.microsoft.com/en-us/graph/search-concept-files
    endpoint_url = "https://graph.microsoft.com/v1.0/search/query"
    
    data = {
        "requests":[
            {
                "entityTypes" : [
                    "driveItem"
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

        # sharepoint search operation successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}
                search_results = raw_response.json()['value']
                for search_match in search_results:
                    for hits in search_match['hitsContainers']:
                        for hit in hits['hits']:
                            pretty_response[hit["hitId"]] = {
                                "Name" : hit.get('resource','N/A').get('name', 'N/A'),
                                "Summary" : hit.get('summary','N/A'),
                                "Size" : hit.get('resource','N/A').get('size','N/A'),
                                "Created By" : hit.get('resource','N/A').get('createdBy','N/A'),
                                "Web URL" : hit.get('resource','N/A').get('webUrl','N/A')
                            }
                return True, raw_response.json(), pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response.json(), None
        
        # sharepoint search operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Search Keyword", "id" : "sp-one-drive-search-keyword-text-input", "type" : "text", "placeholder" : "secrets", "element_type" : "dcc.Input"}
    ]