import requests
import json
from core.EntraAuthFunctions import CreateHeader, FetchSelectedToken

graph_base_url = "https://graph.microsoft.com/v1.0/"

#Function to make GET request to Graph
def graph_get_request(url,pagination=True):

    headers = CreateHeader(FetchSelectedToken())
    graph_results = []
        
    while url:
        try:
            graph_result = requests.get(url=url, headers=headers).json()

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
        except:
            print("GET request failed!")
            break
    print('GET request successful')
    return graph_results

#Function to make a POST request to Graph
def graph_post_request(url, data):
    headers = CreateHeader(FetchSelectedToken())

    try:
        graph_result = requests.post(url=url, headers = headers, data=json.dumps(data))

        if graph_result.status_code in [200,201,202,204,205,206]:
            print("POST request successful!")
            if graph_result.status_code in [204,202]:
                return graph_result
            else:
                return graph_result.json()
        else:
            print(f"POST request failed: {graph_result.status_code}")
        
    except Exception as e:
        print(e)
        print("POST request failed!")
        return None
    

#Function to make DELETE request to Graph
def graph_delete_request(url):
    headers = CreateHeader(FetchSelectedToken())

    try:
        graph_result = requests.delete(url=url, headers=headers)
        if graph_result.status_code == 204:
            print('DELETE request successfull!')
        else:
            print(graph_result.text)
            print('DELETE request failed!')
    except:
        print(graph_result.raw)
        print(graph_result.status_code)
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

