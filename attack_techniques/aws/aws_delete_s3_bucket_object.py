from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSDeleteS3BucketObject(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1485",
                technique_name="Data Destruction",
                tactics=["Impact"],
                sub_technique_name=None
            )
        ]
        super().__init__("Delete S3 Bucket Object", "Deletes a S3 bucket object or all objects in bucket if no object specified.", mitre_techniques)
        
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            bucket_name:str = kwargs.get("bucket_name", None)
            object_key_name:str = kwargs.get("object_key_name", None)

            if bucket_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/delete_bucket.html

            # Initialize boto3 client
            my_client = boto3.client("s3")

            # List objects in bucket
            all_bucket_object_keys = []

            if object_key_name in [None, ""]:
                # s3 object enumeration to get all objects in bucket
                raw_response = my_client.list_objects_v2(Bucket=bucket_name)
                all_bucket_objects = raw_response['Contents']

                for object in all_bucket_objects:
                    all_bucket_object_keys.append(object.get('Key'))

            # only add object specified to delete list
            else:
                all_bucket_object_keys.append(object_key_name)

            # initialize list to track deleted objects
            deleted_objects = []
            # initialize counter to track deleted objects
            delete_failed_counter = 0

            for object_key in all_bucket_object_keys:
                # Delete objects
                try:
                    raw_response = my_client.delete_object(Bucket = bucket_name, Key = object_key)
                    
                    # Object deleted successfully 
                    if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                        # Add object to deleted objects list
                        deleted_objects.append(object_key)
                        object_delete_counter += 1
                    else:
                        delete_failed_counter +=1
                except:
                    # do nothing - attempt to delete next object
                    delete_failed_counter +=1

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully deleted {len(deleted_objects)} S3 bucket objects",
                "value": {
                    "successful_deletions" : len(deleted_objects), 
                    "failed_deletions" : delete_failed_counter,
                    "deleted_objects" : str(deleted_objects)
                }
            }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to delete S3 bucket objects"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to delete S3 bucket objects"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "bucket_name": {"type": "str", "required": True, "default": None, "name": "S3 Bucket Name", "input_field_type" : "text"},
            "object_key_name": {"type": "str", "required": False, "default": None, "name": "Object Name", "input_field_type" : "text"}
        }