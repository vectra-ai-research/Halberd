from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSEnumerateDynamoDBTables(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1619",
                technique_name="Cloud Storage Object Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Dynamo DB Tables", "Enumerates all tables associated with current account in DynamoDB", mitre_techniques)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            limit: int = kwargs.get("limit", None)
            
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client/list_tables.html

            # Initialize boto3 client
            my_client = boto3.client("dynamodb")

            # list dynamodb tables
            if limit in [None, ""]:
                raw_response = my_client.list_tables()
            else:
                raw_response = my_client.list_tables(
                    Limit = limit
                )

            # operation successful
            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                # Create output
                tables = [table for table in raw_response['TableNames']]

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(tables)} tables in DynamoDB" if tables else "No tables found in DynamoDB",
                    "value": tables
                }

            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('ResponseMetadata'),
                "message": "Failed to enumerate DynamoDB tables"
            }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate DynamoDB tables"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate DynamoDB tables"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "limit": {"type": "int", "required": False, "default": None, "name": "Limit", "input_field_type" : "number"}
        }