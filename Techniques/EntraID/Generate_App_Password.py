'''
Module Name: Generate_App_Password
Description: Generate new password for an application
Reference: https://learn.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0&tabs=http
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(app_id, cred_display_name):

    # input validation
    if app_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if cred_display_name in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    endpoint_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/addPassword"

    # provide user friendly display name for the new credential
    data = {
        "passwordCredential": {
            "displayName": cred_display_name
        }
    }

    try:
        raw_response = graph_post_request(url = endpoint_url, data = data)

        # create app credential operation successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # generate pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    "Key Id" : raw_response.json().get("keyId", "N/A"),
                    "Secret Text" : raw_response.json().get("secretText", "N/A"),
                    "Display Name" : raw_response.json().get("displayName", "N/A"),
                    "Custom Key Id" : raw_response.json().get("customKeyIdentifier", "N/A"),
                    "Start Date Time" : raw_response.json().get("startDateTime", "N/A"),
                    "End Date Time" : raw_response.json().get("endDateTime", "N/A")
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
        
        # generate app credential operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Application (Object) ID", "id" : "app-id-text-input", "type" : "text", "placeholder" : "1bf9g6g2-81d8-8427-ck09-21b13c0473f9", "element_type" : "dcc.Input"},
        {"title" : "Cred Display Name", "id" : "cred-display-text-input", "type" : "text", "placeholder" : "Hacker Password", "element_type" : "dcc.Input"}
    ]