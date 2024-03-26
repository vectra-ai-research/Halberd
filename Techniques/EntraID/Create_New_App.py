'''
Module Name: Create_New_App
Module Description: Create a new application in tenant
Reference: https://learn.microsoft.com/en-us/graph/api/application-post-applications?view=graph-rest-1.0&tabs=http
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(app_name):
    
    # input validation
    if app_name in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    endpoint_url = "https://graph.microsoft.com/v1.0/applications"

    # provide new application display name
    data = {
        "displayName": app_name
    }

    try:
        raw_response = graph_post_request(url = endpoint_url, data = data)

        # create new application operation successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    'Message' : "New application created",
                    'App Display Name' : app_name
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
        
        # create new application operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "New Application Name", "id" : "app-name-text-input", "type" : "text", "placeholder" : "hacker-app", "element_type" : "dcc.Input"},
    ]