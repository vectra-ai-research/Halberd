#Discover Conditional Access Policies
from core.GraphFunctions import graph_get_request
from dash import html

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    tenant_caps = graph_get_request(url = endpoint_url)
    print("Tenant CAPs found")
    
    return tenant_caps


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return []