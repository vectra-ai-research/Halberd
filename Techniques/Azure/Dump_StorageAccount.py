from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient

import json

def TechniqueMain(subscription_id):
    """Function to get Storage Account Keys"""
    try:
        # Initialize Azure credentials and clients
        credential = DefaultAzureCredential()
        resource_client = ResourceManagementClient(credential, subscription_id)
        storage_client = StorageManagementClient(credential, subscription_id)

        storage_keys = {}

        # List resource groups
        resource_groups = resource_client.resource_groups.list()
        for resource_group in resource_groups:
            print("Resource Group", resource_group.name)
            storage_keys[resource_group.name] = {}
            
            try:
                # List storage accounts in each resource group
                storage_accounts = storage_client.storage_accounts.list_by_resource_group(resource_group.name)
                for storage_account in storage_accounts:
                    print("  Storage Account", storage_account.name)
                    keys = storage_client.storage_accounts.list_keys(resource_group.name, storage_account.name)
                    storage_keys[resource_group.name][storage_account.name] = []
                    # Store keys for each storage account
                    if keys:
                        for key in keys.keys:
                            # Construct connection string using the first key
                            connection_string = (
                                f"DefaultEndpointsProtocol=https;AccountName={storage_account.name};"
                                f"AccountKey={key.value};EndpointSuffix=core.windows.net"
                            )

                            storage_keys[resource_group.name][storage_account.name].append({
                                "key_name": key.key_name,
                                "key_value": key.value,
                                "connection_string": connection_string

                            })

            except Exception as e:
                print(f"error: {e}")
                    
        # Convert storage keys to JSON format
        storage_keys_json = json.dumps(storage_keys, indent=4)
        return storage_keys_json
    
    except Exception as e:
        print(f"error: {e}")
    

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "subscription_id", "id" : "subscription-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"}
    ]