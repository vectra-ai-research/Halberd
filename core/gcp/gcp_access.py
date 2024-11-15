import base64
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import json
import os
import requests

class GCPAccess(service_account.Credentials):
    """GCP access manager"""
    _instance = None 
    
    def __new__(cls, *args, **kwargs):
        # If an instance already exists, return it
        if cls._instance is None:
            cls._instance = super(GCPAccess, cls).__new__(cls)
        return cls._instance



    def __init__(self, raw_credential, scopes=None):
        """Initialize GCPAccess directly with raw credential string and optional scopes"""
        # Only initialize if it's not already initialized
        if not hasattr(self, '_initialized'):
            self._initialized = True  # Prevent re-initialization

        # Default scope if none provided
        if scopes is None:
            scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        
        try:
            # Decode raw base64 credential if it's encoded (remove the [29:] slice if not needed)
            decoded_credential = json.loads(base64.b64decode(raw_credential[29:]).decode('utf-8'))

            # Load the credentials using the parsed JSON and provided scopes
            credentials = service_account.Credentials.from_service_account_info(
                decoded_credential,
                scopes=scopes
            )

            credentials.refresh(Request())
            
            # Initialize the parent class (service_account.Credentials) with extracted values
            super().__init__(credentials.signer, credentials.service_account_email, credentials._token_uri, scopes=scopes)
            
        except RefreshError as e:
            # Directly raise the exception from __init__ to be caught by the caller
            raise e
        except Exception as e:
            # Raise any other exception that occurs during initialization
            raise e
        
    @classmethod
    def get_validation(self):
        """Validates GCP access"""
        try:
            if self.valid == False:
                return False
            return True
        except:
            return False
        
    @classmethod
    def get_expired_info(self):
        """Gets GCP access expired info"""
        try:
            if self.expired == True:
                return False
            return True
        except:
            return False
        
    @classmethod
    def current_credentials(cls):
        """Returns the current credentials"""
        return cls._instance
        
    @classmethod
    def clear_instance(cls):
        """Clear the singleton instance to allow re-initialization"""
        cls._instance = None
        
    