from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import json
import base64
# from google.auth.exceptions import RefreshError
from core.gcp.gcp_access import GCPAccess
from google.cloud import storage
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.auth.transport.requests import Request



@TechniqueRegistry.register
class GCPEnumerateCloudStorageABucket(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1223",
                technique_name="Data from Cloud Storage",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Cloud Storage Objects on Specific Bucket", "Enumerates Cloud Storage object on a buckets in the targeted GCP account", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            name: str = kwargs['name']
            manager = GCPAccess()
            current_access = manager.get_current_access()
            loaded_credential = json.loads(base64.b64decode(current_access["credential"]))
            scopes = [
                "https://www.googleapis.com/auth/devstorage.read_only"
            ]
            request = Request()
            credential = ServiceAccountCredentials.from_service_account_info(loaded_credential, scopes=scopes)
            credential.refresh(request=request)
            
            client = storage.Client(credentials=credential)

            buckets = client.list_blobs(bucket_or_name=name)

            enumerated_objects = []
            for bucket in buckets:
                enumerated_objects.append("/"+bucket.name)

            return ExecutionStatus.SUCCESS, {
                "value": {
                    "founded": len(enumerated_objects),
                    "buckets": enumerated_objects
                },
                "message": f"Successfully established access to target GCP tenant"
            }
        
        except ValueError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate cloud storage buckets. The project not specified on selected credential or no current saved credential"
            }
        
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access to GCP"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "name": {"type": "str", "required": True, "default": None, "name": "Name", "input_field_type" : "text"},
        }