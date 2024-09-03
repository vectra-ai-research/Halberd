from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSEnumerateIAMRoles(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1069.003",
                technique_name="Permission Groups Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Groups"
            )
        ]
        super().__init__("Enumerate IAM Roles", "Enumerates all IAM roles. Optionally, supply path prefix to enumerate specific roles", mitre_techniques)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            path_prefix:str = kwargs.get("path_prefix", None)
            
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_roles.html

            # Initialize boto3 client
            my_client = boto3.client("iam")

            if path_prefix in [None,""]:
                # list all iam roles
                raw_response = my_client.list_roles()
            else:
                # list roles with supplied path prefix
                raw_response = my_client.list_roles(PathPrefix=path_prefix)
                
            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                # Create output
                roles = [role['RoleName'] for role in raw_response['Roles']]

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(roles)} roles" if roles else "No roles found",
                    "value": roles
                }
            
            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('ResponseMetadata', 'N/A'),
                "message": "Failed to enumerate roles"
            }
        
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate roles"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate roles"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "path_prefix": {"type": "str", "required": False, "default": None, "name": "Role Path Prefix", "input_field_type" : "text"}
        }