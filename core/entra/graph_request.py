import requests
import json
import re
import time
from typing import Optional, Dict, Any, Union, List
import logging
from .entra_token_manager import EntraTokenManager
from core.Constants import SERVER_LOG_FILE

logger = logging.getLogger(__name__)
logging.basicConfig(filename=SERVER_LOG_FILE, format='%(asctime)s - %(levelname)s - %(message)s', level=logging.WARNING)

class RateLimiter:
    """Handles rate limiting for Graph API requests"""
    def __init__(self, requests_per_second: int = 20):
        self.requests_per_second = requests_per_second
        self.last_request_time = 0.0
        self._remaining_requests = None
        self._throttle_until = None

    def wait_if_needed(self, response: Optional[requests.Response] = None) -> None:
        """
        Implements rate limiting based on time between requests and response headers.
        
        Args:
            response: Optional response object to check for throttling headers
        """
        current_time = time.time()

        # Check for throttling headers if response is provided
        if response is not None:
            remaining = response.headers.get('X-RateLimit-Remaining')
            retry_after = response.headers.get('Retry-After')

            if remaining is not None:
                self._remaining_requests = int(remaining)

            if retry_after is not None:
                self._throttle_until = current_time + int(retry_after)
                logger.warning(f"Rate limit hit. Waiting {retry_after} seconds.")
                time.sleep(int(retry_after))
                return

        # If in a throttle window, wait
        if self._throttle_until and current_time < self._throttle_until:
            wait_time = self._throttle_until - current_time
            logger.debug(f"In throttle window. Waiting {wait_time:.2f} seconds.")
            time.sleep(wait_time)
            return

        # Rate limiting based on requests per second
        elapsed = current_time - self.last_request_time
        if elapsed < (1.0 / self.requests_per_second):
            wait_time = (1.0 / self.requests_per_second) - elapsed
            time.sleep(wait_time)

        self.last_request_time = time.time()

class GraphRequest:
    """Handles Microsoft Graph API requests with rate limiting and error handling"""
    
    def __init__(self, requests_per_second: int = 20):
        self.manager = EntraTokenManager()
        self.rate_limiter = RateLimiter(requests_per_second)
        self._session = requests.Session()

    def _get_token(self, access_token: Optional[str]) -> str:
        """Get the access token to use for the request"""
        if access_token:
            return access_token
        return self.manager.get_active_token()

    def _create_headers(self, access_token: Optional[str]) -> Dict[str, str]:
        """Create headers for the request including authorization"""
        token = self._get_token(access_token)
        return self.manager.create_auth_header(token)

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Makes an HTTP request with rate limiting and error handling.
        
        Args:
            method: HTTP method to use
            url: URL to make request to
            **kwargs: Additional arguments to pass to requests
            
        Returns:
            Response from the request
            
        Raises:
            requests.exceptions.RequestException: If the request fails
        """
        self.rate_limiter.wait_if_needed()
        
        try:
            response = self._session.request(method, url, **kwargs)
            self.rate_limiter.wait_if_needed(response)
            if response.status_code == 429:  # Too Many Requests
                retry_after = int(response.headers.get('Retry-After', 30))
                logger.warning(f"Rate limit exceeded. Retrying after {retry_after} seconds")
                time.sleep(retry_after)
                return self._make_request(method, url, **kwargs)
                
            response.raise_for_status()
            return response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return response

    def get(self, url: str, params: Optional[Dict] = None, 
            pagination: bool = True, access_token: Optional[str] = None, 
            stream: Optional[bool] = None) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Make GET request to Graph API with pagination support.
        
        Args:
            url: Graph API endpoint URL
            params: Optional query parameters
            pagination: Whether to handle pagination
            access_token: Optional access token to use
            stream: Whether to stream the response
            
        Returns:
            List of results if paginated, otherwise single result
        """
        headers = self._create_headers(access_token)
        graph_results = []

        while url:
            try:
                response = self._make_request('GET', url, headers=headers, 
                                           params=params, stream=stream)
                result = response.json()
                
                if 'value' in result:
                    graph_results.extend(result['value'])
                else:
                    return result

                url = result.get('@odata.nextLink') if pagination else None
                
            except Exception as e:
                logger.error(f"GET request failed: {str(e)}")
                return e

        return graph_results

    def post(self, url: str, data: Dict[str, Any], 
             access_token: Optional[str] = None) -> requests.Response:
        """Make POST request to Graph API"""
        headers = self._create_headers(access_token)
        try:
            return self._make_request('POST', url, headers=headers, 
                                    data=json.dumps(data))
        except Exception as e:
            logger.error(f"POST request failed: {str(e)}")
            return e

    def delete(self, url: str, access_token: Optional[str] = None) -> requests.Response:
        """Make DELETE request to Graph API"""
        headers = self._create_headers(access_token)
        try:
            return self._make_request('DELETE', url, headers=headers)
        except Exception as e:
            logger.error(f"DELETE request failed: {str(e)}")
            return e

    def patch(self, url: str, data: Dict[str, Any], 
              access_token: Optional[str] = None) -> requests.Response:
        """Make PATCH request to Graph API"""
        headers = self._create_headers(access_token)
        try:
            return self._make_request('PATCH', url, headers=headers, 
                                    data=json.dumps(data))
        except Exception as e:
            logger.error(f"PATCH request failed: {str(e)}")
            return e

    def put(self, url: str, data: Dict[str, Any], 
            access_token: Optional[str] = None) -> Dict[str, Any]:
        """Make PUT request to Graph API"""
        headers = self._create_headers(access_token)
        try:
            response = self._make_request('PUT', url, headers=headers, 
                                        data=json.dumps(data))
            return response.json()
        except Exception as e:
            logger.error(f"PUT request failed: {str(e)}")
            return e

    @staticmethod
    def check_guid(inp_string: str) -> bool:
        """
        Check if a string is a valid GUID.
        
        Args:
            inp_string: String to check
            
        Returns:
            True if string is a valid GUID, False otherwise
        """
        guid_regex = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
        return bool(guid_regex.match(inp_string))