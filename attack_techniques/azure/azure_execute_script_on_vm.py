from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.compute import ComputeManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureExecuteScriptOnVM(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                tactics=["Execution"],
                sub_technique_name=None
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT301.6",
                technique_name="Virtual Machine Scripting",
                tactics=["Execution"],
                sub_technique_name="Vmss Run Command"
            )
        ]
        super().__init__("VM - Execute Scripts/Commands", "Run arbitrary scripts or commands on the target VMs by utilizing the 'RunCommand' feature on a Virtual Machine Scale Set (VMSS). This capability allows installation of malicious software, exfiltrate data, or perform other nefarious activities, potentially compromising the VM instances within the scale set.", mitre_techniques, azure_trm_technique)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            resource_group_name: str = kwargs["resource_group_name"]
            vmss_name: str = kwargs["vmss_name"]

            # Input validation
            if resource_group_name in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": {"input_required": "Resource Group Name"},
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

            # Get VMSS and os type
            vmss = compute_client.virtual_machine_scale_sets.get(resource_group_name, vmss_name)
            os_type = vmss.virtual_machine_profile.storage_profile.os_disk.os_type
            orchestration_mode = vmss.orchestration_mode
            vm_instances = compute_client.virtual_machine_scale_set_vms.list(resource_group_name, vmss.name)
            
            if (os_type == "Windows"):
                run_command_parameters = {
                    'command_id': 'RunPowerShellScript',
                    'script': [
                        "Write-Output 'Hello, this is Halberd!'"
                    ]}
            else:
                run_command_parameters = {
                    'command_id': 'RunShellScript',
                    'script': [
                        "echo 'Hello, this is Halberd!'"
                    ]}

            # Create response
            response = {}
            for vm_instance in vm_instances:
                if (orchestration_mode == "Flexible"):
                    response[vm_instance.name] = compute_client.virtual_machines.begin_run_command(
                        resource_group_name,
                        vm_instance.name,
                        run_command_parameters
                    )
                else:
                    response[vm_instance.name] = compute_client.virtual_machine_scale_set_vms.begin_run_command(
                        resource_group_name,
                        vmss.name,
                        vm_instance.instance_id,
                        run_command_parameters
                    )

            # Return results
            return ExecutionStatus.SUCCESS, {
                "message": f"Script executed on all instances inside the {vmss_name} VMss",
                "value": response
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to execute script on instances"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "resource_group_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"},
            "vmss_name": {"type": "str", "required": True, "default": None, "name": "VMSS Name", "input_field_type" : "text"}
        }