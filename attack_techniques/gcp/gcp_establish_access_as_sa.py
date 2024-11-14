from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import json
import base64


from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError

@TechniqueRegistry.register
class GCPEstablishAccessAsServiceAccount(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.003",
                technique_name="Valid Accounts",
                tactics=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                sub_technique_name="Cloud Accounts"
            )
        ]
        super().__init__("Establish Access As App", "Establishes access to Azure tenant as application", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            # input validation
            credential_raw: str = kwargs['credential']
            
            # Input validationc
            if credential_raw in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            credential_json = json.loads(base64.b64decode(credential_raw[29:]))

            default_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

            
            credential = service_account.Credentials.from_service_account_info(credential_json, scopes=default_scopes)

            
            credential.refresh(Request())

            caller_info_output = {
                'email' : credential.service_account_email,
                'project' : credential.project_id,
                'validity': credential.valid,
                'expired' : credential.expired
            }

            if credential.valid == False:
                return ExecutionStatus.FAILURE, {
                    "error" : str(caller_info_output),
                    "message": "Failed to establish access to GCP. The credential is not valid"
                }
            if credential.expired == True:
                return ExecutionStatus.FAILURE, {
                    "error" : str(caller_info_output),
                    "message": "Failed to establish access to GCP. The credential is expired"
                }
            
            return ExecutionStatus.SUCCESS, {
                "value": str(caller_info_output),
                "message": "Successfully established access to target Azure tenant"
            }
        
        except ValueError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access to GCP. The credential is not valid"
            }
        
        
        except	NotImplementedError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access to GCP. The credential can not be changed. "
            }

        except RefreshError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to refresh access token to GCP"
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access to GCP"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "credential": {"type": "str", "required": True, "default": None, "name": "JSON Credential", "input_field_type" : "upload"}
        }