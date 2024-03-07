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

    result = graph_post_request(url = endpoint_url, data=data)

    return(result)

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Search Keyword", "id" : "sp-one-drive-search-keyword-text-input", "type" : "text", "placeholder" : "secrets", "element_type" : "dcc.Input"}
    ]