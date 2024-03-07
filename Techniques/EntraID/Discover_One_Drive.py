#Discover User One Drive
from core.GraphFunctions import graph_get_request
from dash import html

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/me/drive/root/children"

    drive_items = graph_get_request(url = endpoint_url)
    print("Drive items found")
    
    return drive_items


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return []