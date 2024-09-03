from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraEnumerateSPSites(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Sharepoint Sites", "Enumerates groups in Entra ID", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            endpoint_url = "https://graph.microsoft.com/v1.0/sites"
            
            raw_response = GraphRequest().get(url = endpoint_url)

            if 'error' in raw_response:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" :raw_response.get('error').get('code'),
                              "error_detail" : raw_response.get('error').get('message')
                              },
                    "message": "Failed to enumerate SharePoint sites"
                }
            output = []
            if raw_response:
                output = [({
                    'display_name' : sp_site_info.get('displayName', 'N/A'),
                    'web_url' : sp_site_info.get('webUrl', 'N/A'),
                    'personal_site' : sp_site_info.get('isPersonalSite', 'N/A'),
                    'site_collection' : sp_site_info.get('siteCollection', 'N/A'),
                    'root' : sp_site_info.get('root', 'N/A'),
                    'id' : sp_site_info.get('id', 'N/A'),
                }) for sp_site_info in raw_response]

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(output)} SharePoint sites",
                    "value": output
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No sites found",
                    "value": output
                }


        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate SharePoint sites"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}