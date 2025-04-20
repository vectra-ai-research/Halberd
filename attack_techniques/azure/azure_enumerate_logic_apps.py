from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.logic import LogicManagementClient
from azure.mgmt.resource import ResourceManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureEnumerateLogicApps(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        technique_references = [
            TechniqueReference("Azure Logic Apps Documentation", "https://learn.microsoft.com/en-us/azure/logic-apps/")
        ]
        technique_notes = [
            TechniqueNote("Focus on Logic Apps with HTTP triggers for potential entry points"),
            TechniqueNote("Examine workflow definitions for hardcoded credentials and secrets"),
            TechniqueNote("Look for Logic Apps that connect to other Azure resources like Key Vault"),
            TechniqueNote("Logic Apps can be targeted for persistence mechanisms in Azure environments"),
            TechniqueNote("Try narrowing enumeration to a resource group or using other filters for faster results")
        ]
        super().__init__(
            "Enumerate Logic Apps", 
            "Enumerates Logic Apps deployed across Azure subscriptions, which can reveal automation workflows, integration points, and potential attack vectors in the target environment. Logic Apps often contain sensitive configuration details including API connections, HTTP triggers with webhook URLs, and hardcoded credentials within workflow definitions. This technique can identify these valuable targets for later exploitation, and by analyzing the workflow definitions, an attacker can map out business processes, discover connected systems, and potentially extract credentials or security tokens embedded in the workflows.",
            mitre_techniques,
            references=technique_references,
            notes=technique_notes
        )
        
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            resource_group_name: str = kwargs.get("resource_group_name", None)
            workflow_name: str = kwargs.get("workflow_name", None)
            logic_app_state: str = kwargs.get("logic_app_state", None)
            include_definitions: bool = kwargs.get("include_definitions", False)
            
            # Validate state filter if provided
            valid_states = ["All", "Completed", "Enabled", "Disabled", "Deleted", "Suspended"]
            if logic_app_state and logic_app_state not in valid_states:
                return ExecutionStatus.FAILURE, {
                    "error": f"Invalid state filter. Must be one of: {', '.join(valid_states)}",
                    "message": "Invalid state filter provided"
                }
            
            if logic_app_state == "All":
                state_filter = None # no filter required
            else:
                state_filter = logic_app_state
            
            # Get credential and subscription
            credential = AzureAccess.get_azure_auth_credential()
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # Create clients
            logic_client = LogicManagementClient(credential, subscription_id)
            resource_client = ResourceManagementClient(credential, subscription_id)
            
            logic_apps = []
            total_apps = 0
            
            # Process specific resource group if provided
            if resource_group_name:
                workflow_list = self._get_logic_apps_in_resource_group(
                    logic_client, 
                    resource_group_name, 
                    workflow_name,
                    state_filter,
                    include_definitions
                )
                
                logic_apps.append({
                    "resource_group": resource_group_name,
                    "logic_apps": workflow_list
                })
                total_apps += len(workflow_list)
            else:
                # Process all resource groups
                resource_groups = resource_client.resource_groups.list()
                for rg in resource_groups:
                    try:
                        workflow_list = self._get_logic_apps_in_resource_group(
                            logic_client, 
                            rg.name, 
                            workflow_name,
                            state_filter,
                            include_definitions
                        )
                        
                        if workflow_list:
                            logic_apps.append({
                                "resource_group": rg.name,
                                "logic_apps": workflow_list
                            })
                            total_apps += len(workflow_list)
                    except Exception as e:
                        continue
            
            if total_apps > 0:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {total_apps} Logic Apps",
                    "value": {
                        "result": f"Successfully enumerated {total_apps} Logic Apps",
                        "logic_apps": logic_apps
                    }
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": "No Logic Apps found with the specified criteria",
                    "value": []
                }
            
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate Logic Apps"
            }
    
    def _get_logic_apps_in_resource_group(
            self, 
            logic_client: LogicManagementClient, 
            resource_group_name: str,
            workflow_name: str = None,
            state_filter: str = None,
            include_definitions: bool = False) -> list:
        """Get Logic Apps in a specific resource group with optional filtering"""
        workflow_list = []
        
        # Get either a specific workflow or list all
        if workflow_name:
            try:
                workflow = logic_client.workflows.get(resource_group_name, workflow_name)
                # Apply state filter if provided
                if not state_filter or workflow.state == state_filter:
                    workflow_info = self._extract_workflow_info(workflow, include_definitions, logic_client, resource_group_name)
                    workflow_list.append(workflow_info)
            except Exception:
                # Workflow not found or access denied
                pass
        else:
            # List all workflows in the resource group
            workflows = logic_client.workflows.list_by_resource_group(resource_group_name)
            for workflow in workflows:
                # Apply state filter if provided
                if not state_filter or workflow.state == state_filter:
                    workflow_info = self._extract_workflow_info(workflow, include_definitions, logic_client, resource_group_name)
                    workflow_list.append(workflow_info)
        
        return workflow_list
    
    def _extract_workflow_info(
            self, 
            workflow: Any, 
            include_definitions: bool, 
            logic_client: LogicManagementClient,
            resource_group_name: str) -> Dict[str, Any]:
        """Extract relevant information from a Logic App workflow"""
        workflow_info = {
            "name": workflow.name,
            "id": workflow.id,
            "type": workflow.type,
            "location": workflow.location,
            "state": workflow.state,
            "created_time": str(workflow.created_time) if workflow.created_time else None,
            "changed_time": str(workflow.changed_time) if workflow.changed_time else None,
            "endpoints": self._extract_endpoints(workflow),
            "tags": workflow.tags
        }
        
        # Include workflow definition if requested
        if include_definitions:
            try:
                definition = logic_client.workflows.get(
                    resource_group_name, 
                    workflow.name
                )
                workflow_info["definition"] = definition.definition
                
                # Extract trigger information if available
                workflow_info["triggers"] = self._extract_triggers(definition.definition)
                
                # Extract connections information if available
                workflow_info["connections"] = self._extract_connections(definition.definition)
            except Exception:
                workflow_info["definition"] = "Failed to retrieve workflow definition"
        
        return workflow_info
    
    def _extract_endpoints(self, workflow: Any) -> Dict[str, Any]:
        """Extract endpoints from a Logic App workflow"""
        endpoints = {}
        
        if hasattr(workflow, 'endpoints') and workflow.endpoints:
            for endpoint_type, endpoint_value in workflow.endpoints.__dict__.items():
                if endpoint_value and endpoint_type != 'additional_properties':
                    endpoints[endpoint_type] = endpoint_value
        
        return endpoints
    
    def _extract_triggers(self, definition: Dict[str, Any]) -> Dict[str, Any]:
        """Extract trigger information from workflow definition"""
        triggers = {}
        
        if not definition or not isinstance(definition, dict):
            return triggers
            
        if 'triggers' in definition:
            for trigger_name, trigger_info in definition['triggers'].items():
                trigger_type = trigger_info.get('type', 'Unknown')
                
                # Extract HTTP trigger URLs which can be potential entry points
                if trigger_type == 'Request' or 'Http' in trigger_type:
                    triggers[trigger_name] = {
                        'type': trigger_type,
                        'kind': trigger_info.get('kind', 'Unknown'),
                        'method': trigger_info.get('inputs', {}).get('method', 'Unknown'),
                        'schema': trigger_info.get('inputs', {}).get('schema', {})
                    }
                else:
                    triggers[trigger_name] = {
                        'type': trigger_type,
                        'recurrence': trigger_info.get('recurrence', 'N/A') if trigger_type == 'Recurrence' else 'N/A'
                    }
        
        return triggers
    
    def _extract_connections(self, definition: Dict[str, Any]) -> Dict[str, Any]:
        """Extract connection information from workflow definition"""
        connections = {}
        
        if not definition or not isinstance(definition, dict):
            return connections
            
        if 'parameters' in definition and 'connections' in definition['parameters']:
            conn_params = definition['parameters']['connections']
            for conn_name, conn_info in conn_params.items():
                if isinstance(conn_info, dict) and 'value' in conn_info:
                    conn_value = conn_info['value']
                    if isinstance(conn_value, dict):
                        # Extract connection ID references
                        if 'connectionId' in conn_value:
                            connections[conn_name] = {
                                'connection_id': conn_value['connectionId'],
                                'connection_name': conn_value.get('connectionName', 'Unknown'),
                                'connection_type': conn_value.get('id', 'Unknown').split('/')[-1] if 'id' in conn_value else 'Unknown'
                            }
        
        # Check for embedded connections in actions
        if 'actions' in definition:
            for action_name, action_info in definition['actions'].items():
                if isinstance(action_info, dict) and 'inputs' in action_info:
                    inputs = action_info['inputs']
                    if isinstance(inputs, dict) and 'host' in inputs and 'connection' in inputs['host']:
                        conn_ref = inputs['host']['connection']
                        if isinstance(conn_ref, dict) and 'name' in conn_ref:
                            conn_name = conn_ref['name']
                            if conn_name not in connections:
                                connections[conn_name] = {
                                    'referenced_in_action': action_name,
                                    'action_type': action_info.get('type', 'Unknown')
                                }
        
        return connections

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "resource_group_name": {
                "type": "str", 
                "required": False, 
                "default": None, 
                "name": "Resource Group Name", 
                "input_field_type": "text"
            },
            "workflow_name": {
                "type": "str", 
                "required": False, 
                "default": None, 
                "name": "Logic App Workflow Name", 
                "input_field_type": "text"
            },
            "logic_app_state": {
                "type": "str", 
                "required": False, 
                "default": "All", 
                "name": "Logic App State", 
                "input_field_type": "select",
                "input_list": ["All", "Completed","Enabled","Disabled","Deleted","Suspended"]
            },
            "include_definitions": {
                "type": "bool", 
                "required": False, 
                "default": False, 
                "name": "Include Workflow Definitions", 
                "input_field_type": "bool"
            }
        }