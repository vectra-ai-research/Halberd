from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraEnumerateApps(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1087",
                technique_name="Account Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate Apps", "Enumerates application deployed in Microsoft Entra", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            permission_id: str = kwargs.get('permission_id', None)
            access_token: str = kwargs.get('access_token', None)

            endpoint_url = "https://graph.microsoft.com/v1.0/applications/"

            # recon applications
            if access_token:
                app_recon = GraphRequest().get(url = endpoint_url, access_token=access_token)
            else:
                app_recon = GraphRequest().get(url = endpoint_url)
                
            if 'error' in app_recon:
                return ExecutionStatus.FAILURE, {
                    "error": str(app_recon.get('error', "")),
                    "message": "Failed to recon applications in tenant"
                }
            
            apps_enumerated = []

            for app in app_recon:
                if permission_id:
                    # enumerate through apps to find app with the associated permission
                    required_resource_access = app.get('requiredResourceAccess', [])
                    for resource in required_resource_access:
                        resource_accesses = resource.get('resourceAccess', [])
                        for access in resource_accesses:
                            if access.get('id') == permission_id:
                                apps_enumerated.append({
                                    'display_name' : app.get('displayName', 'N/A'),
                                    'id' : app.get('id', 'N/A'),
                                    'app_id' : app.get('appId', 'N/A')
                                })
                                break
                else:
                    for app in app_recon:
                        apps_enumerated.append({
                            'display_name' : app.get('displayName', 'N/A'),
                            'id' : app.get('id', 'N/A'),
                            'app_id' : app.get('appId', 'N/A'),
                        })
            
            if apps_enumerated:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(apps_enumerated)} apps",
                    "value": apps_enumerated
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": "No applications found in the tenant",
                    "value": []
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to recon applications in tenant"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "permission_id": {"type": "str", "required": False, "default":None, "name": "Permission ID", "input_field_type" : "text"},
            "access_token": {"type": "str", "required": False, "default":None, "name": "Access Token", "input_field_type" : "text"}
        }