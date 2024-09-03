from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
from botocore.exceptions import ClientError

@TechniqueRegistry.register
class AWSDeleteDynamoDBTable(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1485",
                technique_name="Data Destruction",
                tactics=["Impact"],
                sub_technique_name=None
            )
        ]
        super().__init__("Delete DynamoDB Table", "Deletes a table in DyanmoDB for data destruction", mitre_techniques)
        
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            table_name:str = kwargs.get("table_name", None)

            if table_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            # Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client/delete_table.html

            # Initialize boto3 client
            my_client = boto3.client("dynamodb")

            raw_response = my_client.delete_table(TableName = table_name)

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully deleted DynamoDB table {table_name}",
                    "value": {
                        "table_name" : raw_response.get('TableDescription','N/A').get('TableName','N/A'),
                        "table_size_in_bytes" : raw_response.get('TableDescription','N/A').get('TableSizeBytes','N/A'),
                        "item_count" : raw_response.get('TableDescription','N/A').get('ItemCount','N/A'),
                        "tabke_status" : raw_response.get('TableDescription','N/A').get('TableStatus','N/A')
                    }
                }

            return ExecutionStatus.FAILURE, {
                "error": raw_response.get('ResponseMetadata'),
                "message": "Failed to delete DynamoDB table"
            }
        except ClientError as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to delete DynamoDB table"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to delete DynamoDB table"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "table_name": {"type": "str", "required": True, "default": None, "name": "DynamoDB Table Name", "input_field_type" : "text"}
        }