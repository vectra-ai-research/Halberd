#Discover Groups
from core.GraphFunctions import graph_get_request
from dash import html

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/groups"

    tenant_groups = graph_get_request(url = endpoint_url)
    print("Tenant group found")
    
    return tenant_groups


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return []