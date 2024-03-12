'''
Module Name: Generate_App_Password.py
Description: Generate new password for an application
Reference: https://learn.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0&tabs=http
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(app_id, cred_display_name):
    endpoint_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/addPassword"

    # provide user friendly display name for the new credential
    data = {
        "passwordCredential": {
            "displayName": cred_display_name
        }
    }

    # request for credentials
    response = graph_post_request(url = endpoint_url, data= data)

    if response != None:
        # Create output to display
        output_response = {
            "Key Id" : response.get("keyId", "N/A"),
            "Secret Text" : response.get("secretText", "N/A"),
            "displayName" : response.get("displayName", "N/A"),
            "Custom Key Identifier" : response.get("customKeyIdentifier", "N/A"),
            "Start Date Time" : response.get("startDateTime", "N/A"),
            "End Date Time" : response.get("endDateTime", "N/A")
        }
        return output_response
    else:
        return "Failed"

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Application (Object) ID", "id" : "app-id-text-input", "type" : "text", "placeholder" : "1bf9g6g2-81d8-8427-ck09-21b13c0473f9", "element_type" : "dcc.Input"},
        {"title" : "Cred Display Name", "id" : "cred-display-text-input", "type" : "text", "placeholder" : "Hacker Password", "element_type" : "dcc.Input"}
    ]