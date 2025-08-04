from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueReference
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import json
import base64
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from core.gcp.gcp_access import GCPAccess

@TechniqueRegistry.register
class GCPEstablishAccessAsAuthorizedUserApplicationDefault(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1078.004",
                technique_name="Valid Accounts",
                tactics=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                sub_technique_name="Cloud Accounts"
            ),
            MitreTechnique(
                technique_id="T1550.001",
                technique_name="Use Alternate Authentication Material",
                tactics=["Defense Evasion", "Lateral Movement"],
                sub_technique_name="Application Access Token"
            )
        ]

        technique_references = [
            TechniqueReference(ref_title = "Service accounts overview", ref_link = "https://cloud.google.com/iam/docs/understanding-service-accounts")
        ]

        super().__init__("Establish Access with Application Default Credential", "Establish access to Google Cloud Platform using compromised or obtained service account credentials. This technique enables authentication as legitimate GCP service accounts, bypassing traditional user-based authentication mechanisms. The technique accepts service account JSON key files which contain the necessary cryptographic material for authentication including private keys, client information, and token endpoints. Once access is established, you inherit all IAM permissions and roles associated with the compromised service account, enabling privilege escalation and lateral movement within the GCP environment. The technique validates credential integrity, checks for expiration, and can optionally save credentials for persistent access across multiple attack operations.", mitre_techniques=mitre_techniques, references=technique_references)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            # input validation
            raw_credential: str = kwargs['credential']
            name: str = kwargs['name']
            save_and_activate: bool = kwargs['save_and_activate']
            
            # Input validation
            if raw_credential in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            access_manager = GCPAccess(raw_credentials=raw_credential, name=name )
            current_access = access_manager.credential
            
            caller_info_output = {
                'validity': current_access.valid,
                'expired' : current_access.expired
            }

            if access_manager.get_validation() == False:
                caller_info_output["validity"] = False
                return ExecutionStatus.FAILURE, {
                    "error" : str(caller_info_output),
                    "message": "Failed to establish access to GCP. The credential is not valid"
                }
            else :
                caller_info_output["validity"] = True
            
            if access_manager.get_expired_info() == True:
                caller_info_output["expired"] = True
                return ExecutionStatus.FAILURE, {
                    "error" : str(caller_info_output),
                    "message": "Failed to establish access to GCP. The credential is expired"
                }
            else :
                caller_info_output["expired"] = False

            if save_and_activate :
                access_manager.save_credential()

            return ExecutionStatus.SUCCESS, {
                "value": {
                    "credential_info": caller_info_output,
                    "access_status": {
                        "saved": save_and_activate,
                        "activated": save_and_activate,
                        "scopes": current_access.scopes,
                        "token_expiry": str(current_access.expiry) if current_access.expiry else None
                    }
                },
                "message": f"Successfully established access to target GCP tenant"
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
            "credential": {"type": "str", "required": True, "default": None, "name": "Credential Key JSON", "input_field_type" : "upload", "multiple_files": False, "file_type": ".json"},
            "name": {"type": "str", "required": True, "default": None, "name": "Name", "input_field_type" : "text"},
            "save_and_activate": {"type": "bool", "required": False, "default": True, "name": "Save and Activate?", "input_field_type" : "bool"}
        }