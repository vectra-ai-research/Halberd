from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import requests
import json
import base64

@TechniqueRegistry.register
class EntraCheckUserValidity(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1087.004",
                technique_name="Account Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Account"
            )
        ]
        super().__init__("Check User Validity", "Validates if the user/users exist in a target ", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            username: str = kwargs.get('username', None)
            username_file: str = kwargs.get('username_file', None)
            
            if username in [None,""] and username_file == None:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            user_list = []

            # if file provided -> extract usernames from username text file
            if username_file:
                content_string = username_file.split(',')[-1]
                decoded = base64.b64decode(content_string)
                try:
                    text = decoded.decode('utf-8')
                    user_list = text.split('\n')
                    # remove duplicate usernames
                    user_list = list(set(user_list))
                except Exception as e:
                    # file decoding failed
                    return False, {"Error" : e}, None
            else: 
                user_list.append(username)


            # GetCredentialType endpoint
            endpoint_url = "https://login.microsoftonline.com/common/GetCredentialType"
            
            # create request header
            headers = {
                "Content-Type": "application/json"
            }
            
            valid_users = []
            invalid_users =[]

            for user_name in user_list:
                # create request body
                request_body = {
                    "username": user_name,
                    "isOtherIdpSupported": True
                }
                # send request to endpoint
                raw_response = requests.post(endpoint_url, data=json.dumps(request_body), headers=headers)

                # parse data if request is successful
                if raw_response.status_code == 200:
                    target_info = raw_response.json()

                    if target_info.get("IfExistsResult") == 0:
                        valid_users.append({
                            'username' : user_name,
                            'user_valid' : True
                        })
                    else:
                        invalid_users.append({
                            'username' : user_name,
                            'user_valid' : False
                        })
                else:
                    # if request fails, return error code and message
                    return ExecutionStatus.FAILURE, {
                        "error": raw_response.status_code,
                        "message": raw_response.content
                    }
                    
            return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully validated users. {len(valid_users)} user found",
                    "value": {
                        'valid_users' : valid_users,
                        'invalid_users' : invalid_users
                    }
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to validate users in list"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "username": {"type": "str", "required": True, "default":None, "name": "Username", "input_field_type" : "text"},  
            "username_file": {"type": "str", "required": True, "default":None, "name": "Username List File", "input_field_type" : "upload"},
        }