from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest
import re
import requests

@TechniqueRegistry.register
class EntraReconTenantInfo(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Recon Tenant Info", "Recon information related to the target Microsoft tenant ", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            target_domain: str = kwargs.get('target_domain', None)
            authenticated: str = kwargs.get('authenticated', None)

            if target_domain in [None,""]:
                return False, {"Error" : "Domain Name input required"}, None
            
            if authenticated == True:
                # make authenticated request
                endpoint_url = f"https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByDomainName(domainName='{target_domain}')"    
                raw_response = GraphRequest().get(url = endpoint_url)
            else:
                # make unauthenticated request
                endpoint_url = f"https://login.microsoftonline.com/{target_domain}/.well-known/openid-configuration"
                raw_response = requests.get(endpoint_url).json()
    
            if 'error' in raw_response:
                return ExecutionStatus.FAILURE, {
                    "error": {"error_code" :raw_response.get('error').get('code'),
                              "error_detail" : raw_response.get('error').get('message')
                              },
                    "message": "Failed to recon tenant information"
                }

            if authenticated == True:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully gathered tenant information",
                    "value": {
                        'display_name' : raw_response.get('displayName', 'N/A'),
                        'tenant_id' : raw_response.get('tenantId', 'N/A'),
                        'default_domain_name' : raw_response.get('defaultDomainName', 'N/A'),
                        'federation_brand_name' : raw_response.get('federationBrandName', 'N/A')
                    }
                }
            else:
                # extract tenant id
                pattern = r"([a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12})"
                match = re.search(pattern, raw_response['token_endpoint'], re.IGNORECASE)
                tenant_id = match.group(1)

                return ExecutionStatus.SUCCESS, {
                    "message": f"No groups found",
                    "value": {
                        'tenant_iD' : tenant_id,
                        'domain_name' : target_domain,
                        'token_endpoint' : raw_response.get('token_endpoint', 'N/A'),
                        'scopes_supported' : raw_response.get('scopes_supported', 'N/A')
                    }
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to recom tenant information"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target_domain": {"type": "str", "required": True, "default":None, "name": "Target Domain", "input_field_type" : "text"},
            "authenticated": {"type": "bool", "required": False, "default":False, "name": "Authenticated Attempt?", "input_field_type" : "bool"}
        }