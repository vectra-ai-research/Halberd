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
class GCPEnumerateCloudStorageBuckets(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1619",
                technique_name="Cloud Storage Object Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Cloud Storage Buckets", "Enumerates Cloud Storage buckets in the targeted GCP account", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            location: str = kwargs['location']
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

            buckets = client.list_buckets()

            enumerated_buckets = []
            for bucket in buckets:
                bucket_detail = {
                    "name" : bucket.name,
                    "zone" : bucket.location
                }

                if location:
                    if bucket.location == location.upper() :
                        enumerated_buckets.append(bucket_detail)
                else: 
                    enumerated_buckets.append(bucket_detail)
                

            return ExecutionStatus.SUCCESS, {
                "value": {
                    "founded": len(enumerated_buckets),
                    "buckets": enumerated_buckets
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
            "location": {"type": "str", "required": False, "default": None, "name": "Location", "input_field_type" : "text"},
        }