from enum import Enum
from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple, List
from azure.mgmt.logic import LogicManagementClient
from azure.mgmt.resource import ResourceManagementClient
from core.azure.azure_access import AzureAccess
import re

class ConfidenceLevel(Enum):
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"

@TechniqueRegistry.register
class AzureScanLogicAppsForCredentials(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1552.001",
                technique_name="Unsecured Credentials",
                tactics=["Credential Access"],
                sub_technique_name="Credentials In Files"
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT605",
                technique_name="Resource Secret Reveal",
                tactics=["Credential Access"],
                sub_technique_name=None
            )
        ]
        super().__init__(
            "Scan Logic Apps for Credentials", "Performs a deep inspection of Azure Logic Apps to discover exposed credentials and sensitive information. Enumerates all accessible Logic Apps in specified resource group or across entire subscription. Gathers complete workflow definitions, parameters, and connections. Performs pattern matching with configurable confidence levels (high/medium/low). The technique is particularly effective at finding credentials that are often embedded in Logic Apps during workflow automation configuration.", mitre_techniques, azure_trm_technique
        )

    def _get_patterns_by_confidence(self) -> Dict[str, Dict[str, Dict[str, str]]]:
        """Returns regex patterns categorized by confidence level"""
        return {
            ConfidenceLevel.HIGH.value: {
                'client_secret': r'(?:client[_-]?secret|secret)["\s]*[:=]\s*(?:["\']([a-zA-Z0-9\-_\.~]{1,40})["\']|([a-zA-Z0-9\-_\.~]{1,40})(?:\s|,|\}|$))',
                'storage_key': r'(?:storage[_-]?key|storage[_-]?account[_-]?key)["\s]*[:=]\s*(?:["\']([a-zA-Z0-9+/=]{88})["\']|([a-zA-Z0-9+/=]{88})(?:\s|,|\}|$))',
                'connection_string': r'(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.\w+\.[A-Za-z]{1,3})',
                'sas_connection_string': r'(?:(?:BlobEndpoint|QueueEndpoint|TableEndpoint|FileEndpoint)=https://[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.core\.[a-zA-Z0-9.]+[^;]*;)?SharedAccessSignature=[^;\s]+',
                'access_token': r'(?:eyJ[a-zA-Z0-9_-]*\.){2}[a-zA-Z0-9_-]*',
                'certificate_thumbprint': r'thumbprint["\s]*[:=]\s*(?:["\']([a-fA-F0-9]{40})["\']|([a-fA-F0-9]{40})(?:\s|,|\}|$))',
            },
            ConfidenceLevel.MEDIUM.value: {
                'client_secret': r'''(?:secret)['"\s]*[:=]['"\s]*([a-zA-Z0-9\-_\.~]{1,40})['"\s]*''',
                'storage_key': r'(?:storage[-_]?key|account[-_]?key)["\s]*[:=]\s*["\']{0,1}([^"\'\s\{\}\[\]]{8,})[\s,\}\]]',
                'connection_string': r'(?:connection[-_]?string|connstr)["\s]*[:=]\s*["\']{0,1}([^"\'\s\{\}\[\]]{8,})[\s,\}\]]',
                'sas_connection_string': r'(?:(?:BlobEndpoint|QueueEndpoint|TableEndpoint|FileEndpoint)=https://[^;]+;)?SharedAccessSignature=[^;\s]+',
                'api_key': r'(?:api[-_]?key|apikey)[\"\'\s]*[:=][A-Za-z^\"\'\s\{\}\[\]]{8,}',
            },
            ConfidenceLevel.LOW.value: {
                'generic_secret': r'(?:secret|key|token|password|pwd|credential)["\s]*[:=]\s*["\']{0,1}([^"\'\s\{\}\[\]]{4,})',
                'connection_value': r'(?:connection|endpoint|auth)["\s]*[:=]\s*["\']{0,1}([^"\'\s\{\}\[\]]{4,})',
                'generic_base64': r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
                'possible_key': r'(?:[A-Za-z0-9_\-\.~]{16,})',
            }
        }

    def _validate_potential_secret(self, secret: str, confidence_level: str) -> bool:
        """Validates potential secrets with rules based on confidence level"""
        if not secret:
            return False

        # Basic validation for all levels
        if len(secret) < 4:
            return False

        # Common test values to exclude
        common_values = ['placeholder', 'changeme', 'yourkey', 'yoursecret', 'testsecret', 
                        'example', 'default', 'password', 'mypassword', '<secret>', 'your-secret-here']
        if any(value == secret.lower() for value in common_values):
            return False

        if confidence_level == ConfidenceLevel.HIGH.value:
            # Strict validation for high confidence
            char_set = set(secret)
            if len(char_set) < 6:  # Require higher entropy
                return False
            if not any(c.isdigit() for c in secret):  # Require at least one number
                return False
            if len(secret) < 8:  # Require minimum length
                return False
            
        elif confidence_level == ConfidenceLevel.MEDIUM.value:
            # Medium validation
            char_set = set(secret)
            if len(char_set) < 4:  # Require moderate entropy
                return False
            if len(secret) < 6:  # Require moderate length
                return False

        # Low confidence accepts most values that pass basic validation
        return True

    def _scan_for_credentials(self, content: str, confidence_level: str, search_pattern: str = None) -> List[Dict[str, Any]]:
        """Scans content for credentials using patterns matching the specified confidence level"""
        findings = []
        
        if search_pattern:
            # Use custom search pattern
            matches = re.finditer(search_pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                secret = next((g for g in match.groups() if g is not None), match.group(0))
                if self._validate_potential_secret(secret, confidence_level):
                    findings.append({
                        "confidence": confidence_level,
                        "pattern": "custom_search",
                        "match": match.group(0),
                        "secret_value": secret,
                        "context": content[max(0, match.start()-50):match.end()+50].strip()
                    })
        else:
            # Use confidence-based patterns
            patterns = self._get_patterns_by_confidence()
            
            # Include patterns from selected confidence level and higher
            confidence_levels = [ConfidenceLevel.LOW.value, ConfidenceLevel.MEDIUM.value, ConfidenceLevel.HIGH.value]
            selected_index = confidence_levels.index(confidence_level)
            active_levels = confidence_levels[selected_index:]

            for level in active_levels:
                for pattern_name, pattern in patterns[level].items():
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        secret = next((g for g in match.groups() if g is not None), match.group(0))
                        if self._validate_potential_secret(secret, level):
                            findings.append({
                                "confidence": level,
                                "pattern": pattern_name,
                                "match": match.group(0),
                                "secret_value": secret,
                                "context": content[max(0, match.start()-50):match.end()+50].strip()
                            })

        return findings

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            resource_group_name: str = kwargs.get("resource_group_name", None)
            search_pattern: str = kwargs.get("search_pattern", None)
            confidence_level: str = kwargs.get("confidence_level", ConfidenceLevel.HIGH.value)

            # Validate confidence level
            if confidence_level not in [e.value for e in ConfidenceLevel]:
                confidence_level = ConfidenceLevel.HIGH.value

            # Get credential and subscription
            credential = AzureAccess.get_azure_auth_credential()
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # Create clients
            logic_client = LogicManagementClient(credential, subscription_id)
            resource_client = ResourceManagementClient(credential, subscription_id)

            findings = []
            stats = {
                "apps_scanned": 0,
                "apps_with_findings": 0,
                "error_count": 0,
                "findings_by_confidence": {
                    ConfidenceLevel.HIGH.value: 0,
                    ConfidenceLevel.MEDIUM.value: 0,
                    ConfidenceLevel.LOW.value: 0
                }
            }

            if resource_group_name:
                rg_list = [resource_group_name]
            else:
                rg_list = [rg.name for rg in resource_client.resource_groups.list()]

            for rg_name in rg_list:
                try:
                    logic_apps = logic_client.workflows.list_by_resource_group(rg_name)
                    for app in logic_apps:
                        try:
                            stats["apps_scanned"] += 1
                            workflow = logic_client.workflows.get(rg_name, app.name)
                            
                            app_findings = []
                            
                            # Scan definition
                            definition_findings = self._scan_for_credentials(
                                str(workflow.definition),
                                confidence_level,
                                search_pattern
                            )
                            if definition_findings:
                                app_findings.extend(definition_findings)

                            # Scan parameters
                            param_findings = self._scan_for_credentials(
                                str(workflow.parameters),
                                confidence_level,
                                search_pattern
                            )
                            if param_findings:
                                app_findings.extend(param_findings)

                            if app_findings:
                                stats["apps_with_findings"] += 1
                                for finding in app_findings:
                                    stats["findings_by_confidence"][finding["confidence"]] += 1
                                
                                findings.append({
                                    "logic_app_name": app.name,
                                    "resource_group": rg_name,
                                    "location": app.location,
                                    "state": workflow.state,
                                    "findings": app_findings
                                })

                        except Exception as e:
                            stats["error_count"] += 1
                            print(f"Error scanning Logic App {app.name}: {str(e)}")
                            continue

                except Exception as e:
                    stats["error_count"] += 1
                    print(f"Error accessing resource group {rg_name}: {str(e)}")
                    continue

            return ExecutionStatus.SUCCESS, {
                "message": f"Scan completed with confidence level: {confidence_level}. Found potential credentials in {stats['apps_with_findings']} Logic Apps",
                "value": {
                    "findings": findings,
                    "statistics": stats
                }
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to scan Logic Apps"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "resource_group_name": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Resource Group Name",
                "input_field_type": "text"
            },
            "search_pattern": {
                "type": "str",
                "required": False,
                "default": None, 
                "name": "Custom Search Pattern",
                "input_field_type": "text"
            },
            "confidence_level": {
                "type": "str",
                "required": False,
                "default": "high",
                "name": "Confidence Level (low/medium/high)",
                "input_field_type": "text"
            }
        }