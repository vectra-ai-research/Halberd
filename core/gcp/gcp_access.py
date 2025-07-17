import base64
from datetime import datetime, timedelta
import os
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.oauth2.credentials import Credentials as UserAccountCredentials
from google.oauth2.credentials import Credentials as ShortLivedTokenCredentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import json
import requests
from core.Constants import GCP_CREDS_FILE

class GCPAccess():
    """GCP access manager"""
    credential = None
    credential_type: str = None

    def __init__(self, token=None, raw_credentials=None, scopes=None, name=None):
        """Initialize GCPAccess directly with raw credential string and optional scopes"""
        # Only initialize if it's not already initialized
        if raw_credentials != None or token != None:
            # Default scope if none provided
            if scopes is None:
                scopes = ["https://www.googleapis.com/auth/cloud-platform"]
            
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


                    # Detect credential type and initialize
                    if self._is_service_account(loaded_credentials):
                        self.credential = ServiceAccountCredentials.from_service_account_info(
                            loaded_credentials,
                            scopes=scopes
                        )
                        self.credential.current = True
                        self.credential.name = name
                        self.credential_type = "service_account_private_key"
                    elif self._is_user_account(loaded_credentials):
                        self.credential = UserAccountCredentials.from_authorized_user_info(
                            loaded_credentials,
                            scopes=scopes
                        )
                        self.credential.current = True
                        self.credential.name = name
                        self.credential_type = "user_account"
                elif token is not None and raw_credentials is None:
                    # Initialize with short-lived token
                    self.credential = ShortLivedTokenCredentials(
                        token=token,
                        scopes=scopes,
                    )
                    self.credential.current = True
                    self.credential.name = name
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
            # elif isinstance(self.credential, UserAccountCredentials):
            #     return True
            elif isinstance(self.credential, ShortLivedTokenCredentials):
                response_state, token_info = self._get_token_info(self.credential.token)
    
                if response_state == True:
                    now = datetime.now()
                    new_time = now + timedelta(seconds=float(token_info.get("expires_in", 0)))
                    readable_str = new_time.strftime("%Y-%m-%d %H:%M:%S")
                    return False, readable_str
                else:
                    return True, None
                # Short-lived tokens do not have an expiry, so we assume they are always valid
                
            
        except RefreshError as e:
            raise e
        except Exception as e:
            raise e
    
    
    def save_credential(self):
        """Save credential"""
        try :
            self.set_deactivate_current_credentials()
            if self.credential == None:
                raise ValueError("No credential to save")
            if self.credential.name == None:
                raise ValueError("Credential name is required")
            if self.credential.current == None:
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
            # Prepare the credential dictionary to be saved
            # Determine the credential type more reliably
            if not hasattr(self, "encoded_credential") and isinstance(self.credential, ShortLivedTokenCredentials):
                cred_type = "short_lived_token"
            elif isinstance(self.credential, ServiceAccountCredentials):
                cred_type = "service_account_private_key"
            elif isinstance(self.credential, UserAccountCredentials):
                cred_type = "user_account"
            else:
                cred_type = None

            credential_to_saved = {
                "name": getattr(self.credential, "name", None),
                "current": getattr(self.credential, "current", False),
                "type": cred_type,
                "credential": (
                    self.encoded_credential.decode('utf-8')
                    if hasattr(self, "encoded_credential")
                    else base64.b64encode(
                        json.dumps(
                            self.credential.to_json() if hasattr(self.credential, "to_json") else {}
                        ).encode('utf-8')
                    ).decode('utf-8')
                ),
            }

            # if cred_type == "short_lived_token":
            #     # Attempt to get expiration date from token info endpoint
            #     try:
            #         token_info = self._get_token_info(self.credential.token)
            #         expires_in = token_info.get("expires_in")
            #         expiration_date = (datetime.now() + timedelta(seconds=float(expires_in))).strftime("%Y-%m-%d %H:%M:%S")
            #         credential_to_saved["expiration_date"] = expiration_date
            #     except Exception:
            #         credential_to_saved["expiration_date"] = None

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
          
            
    
    def get_current_access(self):
        """Returns the current saved credentials"""
        credentials = self.list_credentials()
        for credential in credentials:
            if credential["current"] == True:
                return credential
        raise ValueError("No current saved credential")
        
    
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
    def _get_token_info(token: str):
        """
        Get detailed information about a GCP OAuth2 token using Google's tokeninfo endpoint.
        Returns the token info as a dictionary if valid, otherwise raises an exception.
        """
        response = requests.get(
            "https://www.googleapis.com/oauth2/v1/tokeninfo",
            params={"access_token": token}
        )
        if response.status_code == 200:
            return True, response.json()
        else:
            return False, None