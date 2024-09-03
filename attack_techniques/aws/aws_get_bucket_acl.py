from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSGetS3BucketACL(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1619",
                technique_name="Cloud Storage Object Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Get S3 Bucket ACL", "Gets S3 bucket ACL information", mitre_techniques)
        
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            bucket_name: str = kwargs.get("bucket_name", None)

            if bucket_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }

            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/get_bucket_acl.html
            
            # Initialize boto3 client
            my_client = boto3.client("s3")

            # Enumerate S3 buckets
            raw_response = my_client.get_bucket_acl(Bucket=bucket_name)

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                # Create output
                acl_info = {
                    'owner': raw_response.get('Owner', 'N/A').get('DisplayName','N/a'),
                    'owner_id' : raw_response.get('Owner', 'N/A').get('ID','N/a'),
                    'grants' : raw_response.get('Grants', 'N/A')
                }    
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully colected S3 bucket ACL information",
                    "value": acl_info
                }

            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('ResponseMetadata','N/A'),
                "message": "ailed to collect S3 bucket ACL information"
            }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to collect S3 bucket ACL information"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "bucket_name": {"type": "str", "required": True, "default": None, "name": "S3 Bucket Name", "input_field_type" : "text"}
        }