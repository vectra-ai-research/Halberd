from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSReconIAMUserInfo(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1087.004",
                technique_name="Account Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Account"
            )
        ]
        super().__init__("Recon IAM User Info", "Retrieves information about a user in AWS", mitre_techniques)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            username: str = kwargs.get("username", None)

            if username in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/get_user.html

            # Initialize boto3 client
            my_client = boto3.client("iam")
        
            raw_response = my_client.get_user(UserName=username)

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully collected user information",
                    "value": {
                        'username': raw_response.get('User', 'N/A').get('UserName','N/a'),
                        'user_id' : raw_response.get('User', 'N/A').get('UserId','N/A'),
                        'arn' : raw_response.get('User', 'N/A').get('Arn','N/A'),
                        'create_date' : raw_response.get('User', 'N/A').get('CreateDate','N/A'),
                        'password_last_used' : raw_response.get('User', 'N/A').get('PasswordLastUsed','N/A'),
                        'permissions_boundary' : raw_response.get('User', 'N/A').get('PermissionsBoundary','N/A'),
                        'tags' : raw_response.get('User', 'N/A').get('Tags','N/A')
                    }
                }

            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('error').get('message', 'N/A'),
                "message": "Failed to recon IAM user info"
            }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to recon IAM user info"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to recon IAM user info"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "username": {"type": "str", "required": True, "default": None, "name": "Target Username", "input_field_type" : "text"}
        }