import base64
import os
from typing import Union
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.oauth2.credentials import Credentials as UserAccountCredentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import json
from core.Constants import GCP_CREDS_FILE

class GCPAccess():
    """GCP access manager"""
    credential = None
    



    def __init__(self, raw_credentials, scopes=None, name=None):
        """Initialize GCPAccess directly with raw credential string and optional scopes"""
        # Only initialize if it's not already initialized

        # Default scope if none provided
        if scopes is None:
            scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        
        try:
            # Check if raw_credentials is Base64-encoded, decode if true
            if self._is_base64(raw_credentials):
                raw_credentials = base64.b64decode(raw_credentials[29:]).decode("utf-8")

            self.encoded_credential=base64.b64encode(raw_credentials.encode())
            # # Load the credentials using the parsed JSON and provided scopes
            # credentials = service_account.Credentials.from_service_account_info(
            #     raw_credentials,
            #     scopes=scopes
            # )
            
            # # Initialize the parent class (service_account.Credentials) with extracted values
            # super().__init__(credentials.signer, credentials.service_account_email, credentials._token_uri, scopes=scopes)


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
            elif self._is_user_account(loaded_credentials):
                self.credential = UserAccountCredentials.from_authorized_user_info(
                    loaded_credentials,
                    scopes=scopes
                )
                self.credential.current = True
                self.credential.name = name
            else:
                raise ValueError("Invalid credential type. Must be Service Account or User Account.")
            
        except ValueError as e:
            raise e
        
        except Exception as e:
            raise e
    
    
    
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
        """Validates GCP access"""
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
            self.refresh_token()
            if self.credential.expired == True:
                return True
            return False
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
            credential_to_saved = {
                "name": self.credential.name,
                "current": self.credential.current,
                "credential": self.encoded_credential.decode('utf-8')
            }

            data.append(credential_to_saved)
            
            with open(GCP_CREDS_FILE, 'w') as file:
                json.dump(data, file)

        except ValueError as e:
            raise e
    
    def list_credentials(self) -> Union[ServiceAccountCredentials,UserAccountCredentials]:
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
        filtered_credentials = None
        for credential in credentials:
            if credential["current"] == False:
                filtered_credentials.append(credential)
            else :
                return False
            
    
    def current_saved_credential(self):
        """Returns the current saved credentials"""
        credentials = self.list_credentials()
        for credential in credentials:
            if credential["current"] == True:
                return credential
            else :
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
        credentials = self.list_credentials()
        for credential in credentials:
            if credential["name"] == name:
                credential["current"] = True
            else :
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