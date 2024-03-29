import requests
import json
import re
from core.EntraAuthFunctions import CreateHeader, FetchSelectedToken

graph_base_url = "https://graph.microsoft.com/v1.0/"

#Function to make GET request to Graph
def graph_get_request(url, params = None, pagination = True):

    headers = CreateHeader(FetchSelectedToken())
    graph_results = []
        
    while url:
        try:
            graph_result = requests.get(url=url, headers=headers, params=params).json()

            if 'value' in graph_result.keys():
                graph_results.extend(graph_result['value'])
            else:
                return graph_result

            if (pagination == True):
                if '@odata.nextLink' in graph_result.keys():
                    url = graph_result['@odata.nextLink']
                else:
                    url = None
            else:
                url = None
        except Exception as e:
            print("GET request failed!")
            return e
    return graph_results

# Function to make a POST request to Graph
def graph_post_request(url, data):
    headers = CreateHeader(FetchSelectedToken())

    try:
        graph_result = requests.post(url=url, headers = headers, data=json.dumps(data))
        return graph_result

    except Exception as e:
        return e

# Function to make DELETE request to Graph
def graph_delete_request(url):
    headers = CreateHeader(FetchSelectedToken())

    try:
        graph_result = requests.delete(url=url, headers=headers)
    except Exception as e:
        return e

    return graph_result

#Function to make PATCH request to Graph
def graph_patch_request(url, data):
    headers = CreateHeader(FetchSelectedToken())

    try:
        graph_result = requests.post(url=url, headers = headers, data=json.dumps(data)).json()
        print('PATCH request successful!')
        return graph_result
        
    except Exception as e:
        print(e)
        print('PATCH request failed!')
        return None

#Function to make a POST request to Graph
def graph_put_request(url, data):
    headers = CreateHeader(FetchSelectedToken())

    try:
        graph_result = requests.put(url=url, headers = headers, data=json.dumps(data)).json()
        print('PUT request successful!')
        return graph_result
        
    except Exception as e:
        print(e)
        print('PUT request failed!')
        return None

def graph_check_guid(inp_string):
    guid_regex = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
    if bool(guid_regex.match(inp_string)):
        return True
    else:
        return False