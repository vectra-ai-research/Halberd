'''
Module Name: Create_New_App.py
Description: Create a new application in tenant
Reference: https://learn.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0&tabs=http
'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(app_name):
    endpoint_url = "https://graph.microsoft.com/v1.0/applications"

    # provide new application display name
    data = {
        "displayName": app_name
    }

    # request app creation
    response = graph_post_request(url = endpoint_url, data= data)
    print(response)

    if response != None:
        return response
    else:
        return "Failed"

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "New Application Name", "id" : "app-name-text-input", "type" : "text", "placeholder" : "hacker-app", "element_type" : "dcc.Input"},
    ]