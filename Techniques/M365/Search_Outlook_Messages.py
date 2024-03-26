'''
Module Name : Search_Outlook_Messages
Description : Recon outlook to collect data
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(search_term):
    endpoint_url = "https://graph.microsoft.com/v1.0/search/query"
    
    data = {
        "requests":[
            {
                "entityTypes" : [
                    "message"
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

        # messages search successfull
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
                                "Subject" : hit.get('resource','N/A').get('subject','N/A'),
                                "Preview" : hit.get('resource','N/A').get('bodyPreview','N/A'),
                                "Summary" : hit.get('summary','N/A'),
                                "Sender" : hit.get('resource','N/A').get('sender', 'N/A').get('emailAddress','N/A'),
                                "Reply To" : hit.get('resource','N/A').get('replyTo', 'N/A'),
                                'Has Attachments' : hit.get('hasAttachments', 'N/A')
                            }
                return True, raw_response.json(), pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response.json(), None
        
        # messages search operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Search Keyword", "id" : "outlook-messages-search-keyword-text-input", "type" : "text", "placeholder" : "secrets", "element_type" : "dcc.Input"}
    ]