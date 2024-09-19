from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.compute import ComputeManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureEnumerateVMInVMSS(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate VM in VMSS ", "Enumerates VMs in Azure Virtual Machine Scale Set (VMSS)", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            rg_name: str = kwargs["rg_name"]
            vmss_name: str = kwargs["vmss_name"]
            
            # Input Validation
            if rg_name in [None,""]:
                return ExecutionStatus.FAILURE, {
                    "error": {"input_required" : "Resource Group name"},
                    "message": "Invalid Technique Input"
                }
            
            if vmss_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": {"input_required": "VMSS Name"},
                    "message": "Invalid Technique Input"
                }

            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # Create client
            compute_client = ComputeManagementClient(credential, subscription_id)
            
            # List resources
            vmss_vm_list = compute_client.virtual_machine_scale_set_vms.list(
                resource_group_name = rg_name,
                virtual_machine_scale_set_name = vmss_name,
            )

            vmss_vms = [vmss_vm_object for vmss_vm_object in vmss_vm_list]

            if vmss_vms:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(vmss)} VM in {vmss_name} VMSS",
                    "value": vmss_vms
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": f"No VMs found in VMSS - {vmss_name}",
                    "value": []
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate VMs in VMSS"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "rg_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"},
            "vmss_name": {"type": "str", "required": True, "default": None, "name": "VMSS Name", "input_field_type" : "text"}
        }