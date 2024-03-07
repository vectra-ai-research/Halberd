#Discover SP Sites
from core.GraphFunctions import graph_get_request
from dash import html

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/sites"

    sp_sites = graph_get_request(url = endpoint_url)
    print("SP Sites found")
    
    return sp_sites


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return []