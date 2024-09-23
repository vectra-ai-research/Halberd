import requests
import json
import re
from .entra_token_manager import EntraTokenManager

class GraphRequest:
    def __init__(self):
        self.manager = EntraTokenManager()

    def _get_token(self, access_token):
        if access_token:
            return access_token
        return self.manager.get_active_token()

    def _create_headers(self, access_token):
        token = self._get_token(access_token)
        return self.manager.create_auth_header(token)

    def get(self, url, params=None, pagination=True, access_token=None):
        """Make GET request to Graph API"""
        headers = self._create_headers(access_token)
        graph_results = []

        while url:
            try:
                graph_result = requests.get(url=url, headers=headers, params=params).json()
                if 'value' in graph_result:
                    graph_results.extend(graph_result['value'])
                else:
                    return graph_result

                if pagination and '@odata.nextLink' in graph_result:
                    url = graph_result['@odata.nextLink']
                else:
                    url = None
            except Exception as e:
                return e

        return graph_results

    def post(self, url, data, access_token=None):
        """Make POST request to Graph API"""
        headers = self._create_headers(access_token)
        try:
            graph_result = requests.post(url=url, headers=headers, data=json.dumps(data))
            return graph_result
        except Exception as e:
            return e

    def delete(self, url, access_token=None):
        """Make DELETE request to Graph API"""
        headers = self._create_headers(access_token)
        try:
            graph_result = requests.delete(url=url, headers=headers)
            return graph_result
        except Exception as e:
            return e

    def patch(self, url, data, access_token=None):
        """Make PATCH request to Graph API"""
        headers = self._create_headers(access_token)
        try:
            graph_result = requests.patch(url=url, headers=headers, data=json.dumps(data))
            return graph_result
        except Exception as e:
            return e

    def put(self, url, data, access_token=None):
        """Make PUT request to Graph API"""
        headers = self._create_headers(access_token)
        try:
            graph_result = requests.put(url=url, headers=headers, data=json.dumps(data)).json()
            return graph_result
        except Exception as e:
            return e

    @staticmethod
    def check_guid(inp_string):
        """Checkf if string is GUID"""
        guid_regex = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
        return bool(guid_regex.match(inp_string))