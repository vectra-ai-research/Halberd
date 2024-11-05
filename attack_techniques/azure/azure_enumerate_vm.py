from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.compute import ComputeManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureEnumerateVm(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1580",
                technique_name="Cloud Infrastructure Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Enumerate VM", "Enumerates compute VMs in the target Azure subscription", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
    
        try:
            credential = AzureAccess.get_azure_auth_credential()
            # retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # create client
            compute_client = ComputeManagementClient(credential, subscription_id)
            
            # list vms
            vm_list = compute_client.virtual_machines.list_all()

            vms = [{'name':vm.name, 'id': vm.id, 'type':vm.type, 'location': vm.location, 'plan':vm.plan} for vm in vm_list]

            if vms:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully enumerated {len(vms)} Azure compute VMs",
                    "value": vms
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": "No VMs found in the account",
                    "value": []
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate Azure compute VMs"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}