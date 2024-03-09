#Discover User One Drive
from core.GraphFunctions import graph_get_request

def TechniqueMain():
    endpoint_url = "https://graph.microsoft.com/v1.0/me/drive/root/children"

    drive_items = graph_get_request(url = endpoint_url)
    
    return drive_items


def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return []