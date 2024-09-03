from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSDeleteS3Bucket(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1485",
                technique_name="Data Destruction",
                tactics=["Impact"],
                sub_technique_name=None
            )
        ]
        super().__init__("Delete S3 Bucket", "Deletes a S3 bucket for data destruction", mitre_techniques)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            bucket_name:str = kwargs.get("bucket_name", None)

            if bucket_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/delete_bucket.html

            # Initialize boto3 client
            my_client = boto3.client("s3")

            raw_response = my_client.delete_bucket(Bucket = bucket_name)

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully deleted S3 bucket {bucket_name}",
                    "value": {
                        "bucket_name" : bucket_name,
                        "message" : "Bucket deleted"
                    }
                }
            
            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('ResponseMetadata'),
                "message": "Failed to delete S3 bucket"
            }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to delete S3 bucket"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to delete S3 bucket"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "bucket_name": {"type": "str", "required": True, "default": None, "name": "S3 Bucket Name", "input_field_type" : "text"}
        }