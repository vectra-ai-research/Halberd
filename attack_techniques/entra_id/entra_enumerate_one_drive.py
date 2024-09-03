from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraEnumerateOneDrive(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Users One Drive", "Enumerates users one drive data", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            endpoint_url = "https://graph.microsoft.com/v1.0/me/drive/root/children"
            
            raw_response = GraphRequest().get(url = endpoint_url)

            if 'error' in raw_response:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" :raw_response.get('error').get('code'),
                              "error_detail" : raw_response.get('error').get('message')
                              },
                    "message": "Failed to enumerate users one drive data"
                }

            output = []
            if raw_response:
                output = [({
                    'name' : item_info.get('name', 'N/A'),
                    'id' : item_info.get('id', 'N/A'),
                    'web_url' : item_info.get('webUrl', 'N/A'),
                    'size' : item_info.get('size', 'N/A'),
                    'created_by' : item_info.get('createdBy', 'N/A')
                }) for item_info in raw_response]

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated users one drive data",
                    "value": output
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No one drive data found",
                    "value": output
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate users one drive data"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}