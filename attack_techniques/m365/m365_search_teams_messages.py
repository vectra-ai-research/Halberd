from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class M365SearchTeamsMessages(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1213",
                technique_name="Data from Information Repositories",
                tactics=["Collection"],
                sub_technique_name=None
            )
        ]
        super().__init__("Search Teams Messages", "Searches teams messages using search query to collect data", mitre_techniques)

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
            
            # Create request payload
            data = {
                "requests":[
                    {
                        "entityTypes" : [
                            "chatMessage"
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
            
            # Request successful
            if 200 <= raw_response.status_code < 300:
                search_results = raw_response.json()['value']

                if search_results:
                    return ExecutionStatus.SUCCESS, {
                        "message": f"Successfully found len{search_results} teams messages",
                        "value": search_results
                    }
                else:
                    return ExecutionStatus.SUCCESS, {
                        "message": f"No teams messages found",
                        "value": []
                    }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": {
                        "error_code": raw_response.json().get('error').get('code', 'N/A'),
                        "eror_message": raw_response.json().get('error').get('message', 'N/A')
                    },
                    "message": "Failed to search teams messages"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to search teams messages"
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