from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3

@TechniqueRegistry.register
class AWSEnumerateCloudtrailTrails(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1087.004",
                technique_name="Account Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Account"
            )
        ]
        super().__init__("Enumerate CloudTrail Trails", "Enumerates all CloudTrail trails in current account", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail/client/list_trails.html

            # Initialize boto3 client
            my_client = boto3.client("cloudtrail")

            # list all cloudtrail trails
            raw_response = my_client.list_trails()

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                # Create output
                trails = [trail for trail in raw_response['Trails']]

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(trails)} trails" if trails else "No trails found",
                    "value": trails
                }
            
            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('ResponseMetadata', 'N/A'),
                "message": "Failed to enumerate CloudTrail trails"
            }
        
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate CloudTrail trails"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}