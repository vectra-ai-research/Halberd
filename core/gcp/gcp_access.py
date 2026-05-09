import base64
from datetime import datetime, timedelta
import os
from dataclasses import dataclass
from typing import Optional, Dict, Any
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.oauth2.credentials import Credentials as UserAccountCredentials
from google.oauth2.credentials import Credentials as ShortLivedTokenCredentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import json
import requests
from core.Constants import GCP_CREDS_FILE

@dataclass
class TokenInfoResponse:
    """Structured response for token info requests"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    status_code: Optional[int] = None
    error: Optional[str] = None

class GCPAccess():
    """GCP access manager"""
    credential = None
    credential_type: str = None
    credential_name: str = None
    credential_current: bool = False

    def __init__(self, token=None, raw_credentials=None, scopes=None, name=None):
        """Initialize GCPAccess directly with raw credential string and optional scopes"""
        # Only initialize if it's not already initialized
        if raw_credentials != None or token != None:
            
            try:
                if raw_credentials is not None and token is None:
                    # Check if raw_credentials is Base64-encoded, decode if true
                    if self._is_base64(raw_credentials):
                        raw_credentials = base64.b64decode(raw_credentials[29:]).decode("utf-8")
                    
                    if isinstance(raw_credentials, dict):
                        raw_credentials = json.dumps(raw_credentials)

                    self.encoded_credential=base64.b64encode(raw_credentials.encode())


                    # Deserialized credential
                    loaded_credentials = json.loads(raw_credentials)

                    # Credential name
                    if name is None:
                        raise ValueError("Credential name is required.")

                    # Default scope if none provided
                    if scopes is None:
                        scopes = ["https://www.googleapis.com/auth/cloud-platform"]

                    # Detect credential type and initialize
                    if self._is_service_account(loaded_credentials):
                        self.credential = ServiceAccountCredentials.from_service_account_info(
                            loaded_credentials,
                            scopes=scopes
                        )
                        self.credential_type = "service_account_private_key"
                    elif self._is_user_account(loaded_credentials):
                        self.credential = UserAccountCredentials.from_authorized_user_info(
                            loaded_credentials,
                            scopes=scopes
                        )
                        if loaded_credentials.get("revoke_uri") is None:
                            self.credential_type = "adc"
                        else:
                            self.credential_type = "regular"
                    self.credential_current = True
                    self.credential_name = name
                elif token is not None and raw_credentials is None:
                    token_response = self._get_token_info(token)
                    
                    if not token_response.success:
                        raise ValueError(f"Failed to validate token with Google tokeninfo endpoint: HTTP {token_response.status_code} - {token_response.error}")

                    # Initialize with short-lived token
                    self.credential = ShortLivedTokenCredentials(
                        token=token,
                        scopes=token_response.data["scope"].split(" ") if "scope" in token_response.data else ["https://www.googleapis.com/auth/cloud-platform"]
                    )
                    self.credential_current = True
                    self.credential_name = name
                    self.credential_type = "short_lived_token"
                else:
                    raise ValueError("Invalid credential type. Must be Service Account or User Account.")
                
            except ValueError as e:
                raise e
            
            except Exception as e:
                raise e
    
    
    def get_detailed_credential(self, name = None, data = None):
        """Get detailed credential"""
        if name != None :
            credentials = self.list_credentials()
            detailed_credential = None
            for credential in credentials:
                if credential["name"] == name:
                    decoded_credential = base64.b64decode(credential["credential"]).decode("utf-8")
                    detailed_credential = {
                        "name": credential["name"],
                        "current": credential["current"],
                        "credential": json.loads(decoded_credential),
                        "type": credential["type"],
                    }
                    return detailed_credential

            raise ValueError("Credential not found")
        if data != None :
            decoded_credential = base64.b64decode(data).decode("utf-8")
            detailed_credential = {
                "name": name,
                "current": False,
                "credential": json.loads(decoded_credential)
            }
            return detailed_credential
        raise ValueError("No credential data provided")

    def refresh_token(self):
        """Refresh the token associated with the credentials."""
        try:
            request = Request()
            self.credential.refresh(request)
        except RefreshError as e:
            raise e
        except Exception as e:
            raise e

    
    def get_validation(self):
        """Validates GCP access, cannot use this method for short-lived token"""
        try:
            self.refresh_token()
            if self.credential.valid == False:
                return False
            return True
        except RefreshError as e:
            raise e
        except Exception as e:
            raise e
        
    
    def get_expired_info(self):
        """Gets GCP access expired info"""
        try:
            if isinstance(self.credential, ServiceAccountCredentials):
                self.refresh_token()
                if self.credential.expired == True:
                    return True, None
                return False, None
            elif self.credential_type == "short_lived_token":
                token_response = self._get_token_info(self.credential.token)
    
                if token_response.success:
                    now = datetime.now()
                    new_time = now + timedelta(seconds=float(token_response.data.get("expires_in", 0)))
                    readable_str = new_time.strftime("%Y-%m-%d %H:%M:%S")
                    return False, readable_str
                else:
                    return True, None
            elif isinstance(self.credential, UserAccountCredentials):
                self.refresh_token()
                if self.credential.expired == True:
                    return True, None
                return False, None
                # return True
            else:
                raise ValueError("Invalid credential type for expired info check")
            
        except RefreshError as e:
            raise e
        except Exception as e:
            raise e
    
    
    def save_credential(self):
        """Save credential"""
        try :
            self.set_deactivate_current_credentials()
            credential_to_check = self.list_credentials()
            if any(cred["name"] == self.credential_name for cred in credential_to_check):
                raise ValueError("Credential name already exists")
            if self.credential == None:
                raise ValueError("No credential to save")
            if self.credential_name == None:
                raise ValueError("Credential name is required")
            if self.credential_current == None:
                raise ValueError("Credential current is required")
            if os.path.exists(GCP_CREDS_FILE):
                with open(GCP_CREDS_FILE,"r") as file:
                    try :
                        data = json.load(file)
                        if not isinstance(data, list):
                            data = []
                    except json.JSONDecodeError:
                        data =[]
            else :
                data = []

            # Prepare credential data for storage
            if hasattr(self, "encoded_credential"):
                credential_data = self.encoded_credential.decode('utf-8')
            elif self.credential_type == "short_lived_token":
                # For short-lived tokens, store token and scopes directly
                token_data = {
                    "token": self.credential.token,
                    "scopes": list(self.credential.scopes) if self.credential.scopes else ["https://www.googleapis.com/auth/cloud-platform"]
                }
                credential_data = base64.b64encode(json.dumps(token_data).encode('utf-8')).decode('utf-8')
            else:
                # For other credential types, to_json() returns a string that needs wrapping
                cred_json = self.credential.to_json() if hasattr(self.credential, "to_json") else {}
                credential_data = base64.b64encode(json.dumps(cred_json).encode('utf-8')).decode('utf-8')

            credential_to_saved = {
                "name": getattr(self, "credential_name", None),
                "current": getattr(self, "credential_current", False),
                "type": getattr(self, "credential_type", None),
                "credential": credential_data,
            }


            data.append(credential_to_saved)
            
            with open(GCP_CREDS_FILE, 'w') as file:
                json.dump(data, file)

        except ValueError as e:
            raise e
    
    def list_credentials(self):
        """List all credentials"""
        try :
            if os.path.exists(GCP_CREDS_FILE):
                with open(GCP_CREDS_FILE, "r") as file:
                    try :
                        data = json.load(file)
                        if not isinstance(data, list):
                            data = []
                    except json.JSONDecodeError:
                        data =[]
            else :
                data = []
            return data
        except ValueError as e:
            raise e

    def delete_current_credentials(self):
        """Delete current credential"""
        credentials = self.list_credentials()
        filtered_credentials = []
        for credential in credentials:
            if credential["current"] == False:
                filtered_credentials.append(credential)
        with open(GCP_CREDS_FILE, 'w') as file:
            json.dump(filtered_credentials, file)
    
    def delete_credential_by_name(self, credential_name: str):
        """Delete a specific credential by name"""
        credentials = self.list_credentials()
        original_count = len(credentials)
        filtered_credentials = []
        
        for credential in credentials:
            if credential["name"] != credential_name:
                filtered_credentials.append(credential)
        
        if len(filtered_credentials) == original_count:
            raise ValueError(f"Credential '{credential_name}' not found")
        
        with open(GCP_CREDS_FILE, 'w') as file:
            json.dump(filtered_credentials, file)
          
            
    
    def get_current_access(self):
        """Returns the current saved credentials"""
        credentials = self.list_credentials()
        if not credentials:
            return None
        for credential in credentials:
            if credential["current"] == True:
                decoded_cred = base64.b64decode(credential["credential"]).decode("utf-8")
                cred_dict = json.loads(decoded_cred)
                if credential["type"] == "service_account_private_key":
                    self.credential = ServiceAccountCredentials.from_service_account_info(
                        cred_dict,
                        scopes=["https://www.googleapis.com/auth/cloud-platform"]
                    )
                elif credential["type"] in ["adc", "regular"]:
                    self.credential = UserAccountCredentials.from_authorized_user_info(
                        cred_dict,
                        scopes=["https://www.googleapis.com/auth/cloud-platform"]
                    )
                elif credential["type"] == "short_lived_token":
                    # Handle double-wrapped JSON (to_json() returns string, then json.dumps wraps it again)
                    if isinstance(cred_dict, str):
                        cred_dict = json.loads(cred_dict)
                    token = cred_dict.get("token")
                    scopes = cred_dict.get("scopes", ["https://www.googleapis.com/auth/cloud-platform"])
                    self.credential = ShortLivedTokenCredentials(token=token, scopes=scopes)
                else:
                    self.credential = cred_dict
                self.credential_type = credential["type"]
                self.credential_name = credential["name"]
                return {
                    "name": credential["name"],
                    "current": credential["current"],
                    "credential": cred_dict,
                    "type": credential["type"],
                }
        return None
        
    
    def set_deactivate_current_credentials(self):
        """Deactivate current credential"""
        credentials = self.list_credentials()
        for credential in credentials:
            if credential["current"] == True:
                credential["current"] = False
            
        with open(GCP_CREDS_FILE, 'w') as file:
            json.dump(credentials, file)
          
    def set_activate_credentials(self, name):
        """Set the credential to activate"""
        self.set_deactivate_current_credentials()
        credentials = self.list_credentials()
        for credential in credentials:
            if credential["name"] == name:
                credential["current"] = True
                with open(GCP_CREDS_FILE, 'w') as file:
                    json.dump(credentials, file)
                break
        else:
            raise ValueError("Credential not found")
        
    

    
    @staticmethod
    def _is_base64(data: str) -> bool:
        """Check if a string is Base64-encoded."""
        if "data:application/json;base64" in data :
            return True
        else :
            return False

    @staticmethod
    def _is_service_account(credentials_data: dict) -> bool:
        """Check if the provided JSON is a Service Account credential."""
        return credentials_data.get("type") == "service_account"

    @staticmethod
    def _is_user_account(credentials_data: dict) -> bool:
        """Check if the provided JSON is a User Account credential."""
        return credentials_data.get("type") == "authorized_user"
    
    @staticmethod
    def _get_token_info(token: str) -> 'TokenInfoResponse':
        """
        Get detailed information about a GCP OAuth2 token using Google's tokeninfo endpoint.
        Returns a TokenInfoResponse object containing success status, token data, and HTTP status code.
        """
        try:
            response = requests.get(
                "https://www.googleapis.com/oauth2/v1/tokeninfo",
                params={"access_token": token},
                timeout=5
            )
            if response.status_code == 200:
                return TokenInfoResponse(
                    success=True,
                    data=response.json(),
                    status_code=response.status_code
                )
            else:
                return TokenInfoResponse(
                    success=False,
                    data=None,
                    status_code=response.status_code,
                    error=f"{response.json().get('error', 'Unknown error')}"
                )
        except Exception as e:
            return TokenInfoResponse(
                success=False,
                data=None,
                status_code=None,
                error=str(e)
            )