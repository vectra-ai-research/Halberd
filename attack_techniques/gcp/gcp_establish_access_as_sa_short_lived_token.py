from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueReference
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from core.gcp.gcp_access import GCPAccess

@TechniqueRegistry.register
class GCPEstablishAccessAsServiceAccountShortLivedToken(BaseTechnique):
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
            TechniqueReference(
                ref_title="Service accounts overview", 
                ref_link="https://cloud.google.com/iam/docs/understanding-service-accounts"
            ),
            TechniqueReference(
                ref_title="Creating short-lived service account credentials", 
                ref_link="https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials"
            ),
            TechniqueReference(
                ref_title="Instance metadata service", 
                ref_link="https://cloud.google.com/compute/docs/storing-retrieving-metadata"
            )
        ]

        super().__init__(
            name="Establish Access with Service Account Short-Lived Token", 
            description="Establish access to Google Cloud Platform using compromised or obtained short-lived access tokens. This technique enables authentication as legitimate GCP service accounts using temporary tokens that may have been extracted from metadata endpoints, stolen from running applications, or obtained through other means. Short-lived tokens provide a limited-time window for access, typically lasting 1 hour before expiration. Once access is established, you inherit all IAM permissions and roles associated with the service account that generated the token, enabling privilege escalation and lateral movement within the GCP environment.", 
            mitre_techniques=mitre_techniques, 
            references=technique_references
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            # input validation
            token: str = kwargs['token']
            name: str = kwargs['name']
            save_and_activate: bool = kwargs['save_and_activate']
            
            # Input validation
            if token in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }

            access_manager = GCPAccess(token=token, name=name)
            current_access = access_manager.credential
            
            caller_info_output = {
                'expired' : True
            }

            expired, readable_str = access_manager.get_expired_info()
            if expired == True:
                caller_info_output["expired"] = True
                return ExecutionStatus.FAILURE, {
                    "error" : str(caller_info_output),
                    "message": "Failed to establish access to GCP. The credential is expired"
                }
            else :
                caller_info_output["expired"] = False
                caller_info_output["expiry"] = readable_str

            if save_and_activate :
                access_manager.save_credential()

            return ExecutionStatus.SUCCESS, {
                "value": {
                    "credential_info": caller_info_output,
                    "access_status": {
                        "saved": save_and_activate,
                        "activated": save_and_activate
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
            "token": {"type": "str", "required": True, "default": None, "name": "Token", "input_field_type" : "text"},
            "name": {"type": "str", "required": True, "default": None, "name": "Name", "input_field_type" : "text"},
            "save_and_activate": {"type": "bool", "required": False, "default": True, "name": "Save and Activate?", "input_field_type" : "bool"}
        }