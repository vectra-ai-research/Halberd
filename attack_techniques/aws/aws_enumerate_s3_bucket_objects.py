from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSEnumerateS3BucketObjects(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1619",
                technique_name="Cloud Storage Object Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate S3 Bucket Objects", "Enumerates S3 buckets in the target AWS account", mitre_techniques)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            bucket_name: str = kwargs.get("bucket_name", None)

            if bucket_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_objects_v2.html
            
            # Initialize boto3 client
            my_client = boto3.client("s3")

            # Enumerate S3 buckets
            raw_response = my_client.list_objects_v2(Bucket=bucket_name)

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                # Create output
                objects = [bucket['Key'] for bucket in raw_response['Contents']]
                
                
                if objects:
                    return ExecutionStatus.SUCCESS, {
                        "message": f"Successfully enumerated {len(objects)} S3 bucket objects" if objects else "No S3 bucket objects found",
                        "value": objects
                    }

            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('ResponseMetadata','N/A'),
                "message": "Failed to enumerate S3 bucket objects"
            }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate S3 bucket objects"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "bucket_name": {"type": "str", "required": False, "default": "us-west-2", "name": "S3 Bucket Name", "input_field_type" : "text"}
        }