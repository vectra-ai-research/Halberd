from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccountUpdateParameters, NetworkRuleSet, DefaultAction

def TechniqueMain(subscription_id, resource_group_name, account_name):
    '''Function to make Storage Account Public'''
    
    # input validation
    if subscription_id in ["", None]:
        return False, {"Error" : "Invalid input : Subscription ID required"}, None
    if resource_group_name in ["", None]:
        return False, {"Error" : "Invalid input : Resource Group Name required"}, None
    if account_name in ["", None]:
        return False, {"Error" : "Invalid input : Account Name required"}, None
    
    
    try:
        credential = DefaultAzureCredential()
        storage_client = StorageManagementClient(credential, subscription_id)

        update_params = StorageAccountUpdateParameters(
            public_network_access='Enabled'
        )
        storage_client.storage_accounts.update(
            resource_group_name,
            account_name,
            update_params
        )

        network_rule_set = NetworkRuleSet(
            default_action=DefaultAction.ALLOW
        )
        storage_client.storage_accounts.update(
            resource_group_name,
            account_name,
            StorageAccountUpdateParameters(network_rule_set=network_rule_set)
        )

        raw_response = {}
        pretty_response = {}                
        pretty_response["Success"] = {
                "message": f"Storage account {account_name} network rule set updated to allow default action."
            }
            
        return True, raw_response, pretty_response

    except Exception as e:
            return False, {"Error" : e}, None
    
    
# Function to define the input fields required for the technique execution
def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Subscription ID", "id" : "subscription-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Resource Group Name", "id" : "resource-group-name-text-input", "type" : "text", "placeholder" : "rg-name", "element_type" : "dcc.Input"},
        {"title" : "Account Name", "id" : "account-name-text-input", "type" : "text", "placeholder" : "storageacctest", "element_type" : "dcc.Input"}
        ]
