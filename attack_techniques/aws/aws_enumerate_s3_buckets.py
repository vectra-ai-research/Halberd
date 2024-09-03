from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSEnumerateS3Buckets(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1619",
                technique_name="Cloud Storage Object Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate S3 Buckets", "Enumerates S3 buckets in the target AWS account", mitre_techniques)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_buckets.html
            
            # Initialize boto3 client
            my_client = boto3.client("s3")

            # Enumerate S3 buckets
            raw_response = my_client.list_buckets()

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                # Create output
                buckets = [bucket['Name'] for bucket in raw_response['Buckets']]
                
                if buckets:
                    return ExecutionStatus.SUCCESS, {
                        "message": f"Successfully enumerated {len(buckets)} S3 buckets" if buckets else "No S3 buckets found",
                        "value": buckets
                    }
            
            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('ResponseMetadata', 'N/A'),
                "message": "Failed to enumerate S3 buckets"
            }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate S3 buckets"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate IAM users"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}