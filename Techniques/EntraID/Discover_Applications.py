'''
Module Name : Discover_Applications.py
Description : recon applications available in the tenant
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/applications/"

    try:
        response = graph_get_request(url = endpoint_url)
        
    except Exception as e:
        return e

    output_response = {}
    for application in response:
        output_response[application['id']] = application

    return output_response


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return []