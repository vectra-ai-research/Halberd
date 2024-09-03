from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class M365SearchUserOneDrive(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1213.002",
                technique_name="Data from Information Repositories",
                tactics=["Collection"],
                sub_technique_name="Sharepoint"
            )
        ]
        super().__init__("Search User One Drive", "Searches users one drive using search query to collect data", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            search_term: str = kwargs.get('search_term', None)

            if search_term in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }

            endpoint_url = "https://graph.microsoft.com/v1.0/search/query"
            # Create payload
            data = {
                "requests":[
                    {
                        "entityTypes" : [
                            "driveItem"
                            ],
                        "query": {
                            "queryString": search_term
                        },
                        "from": 0,
                        "size": 25,
                    }
                ]
            }
            
            raw_response = GraphRequest().post(url = endpoint_url, data = data)
            output = []
            # Request successful
            if 200 <= raw_response.status_code < 300:
                search_results = raw_response.json()['value']
                for search_match in search_results:
                    for hits in search_match['hitsContainers']:
                        for hit in hits['hits']:
                            output.append({
                                "name" : hit.get('resource','N/A').get('name', 'N/A'),
                                "summary" : hit.get('summary','N/A'),
                                "size" : hit.get('resource','N/A').get('size','N/A'),
                                "created_by" : hit.get('resource','N/A').get('createdBy','N/A'),
                                "web_url" : hit.get('resource','N/A').get('webUrl','N/A')
                            })

                if search_results:
                    return ExecutionStatus.SUCCESS, {
                        "message": f"Successfully found len{output} matching resources in one drive",
                        "value": output
                    }
                else:
                    return ExecutionStatus.SUCCESS, {
                        "message": f"No matching resources found in one drive",
                        "value": []
                    }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {
                        "error_code": raw_response.json().get('error').get('code', 'N/A'),
                        "eror_message": raw_response.json().get('error').get('message', 'N/A')
                    },
                    "message": "Failed to find matching resources in one drive"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to find matching resources in one drive"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "search_term": {
                "type": "str", 
                "required": True, 
                "default":None, 
                "name": "Search Keyword", 
                "input_field_type" : "text"
            }
        }