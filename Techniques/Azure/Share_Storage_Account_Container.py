from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, generate_container_sas, ContainerSasPermissions
from azure.mgmt.storage import StorageManagementClient
from datetime import datetime, timedelta, timezone

def TechniqueMain(subscription_id, resource_group_name, account_name, container_name):
    '''Function to generate SAS token for a container'''
    
    # input validation
    if subscription_id in ["", None]:
        return False, {"Error" : "Invalid input : Subscription ID required"}, None
    if resource_group_name in ["", None]:
        return False, {"Error" : "Invalid input : Resource Group Name required"}, None
    if account_name in ["", None]:
        return False, {"Error" : "Invalid input : Account Name required"}, None
    if container_name in ["", None]:
        return False, {"Error" : "Invalid input : Container Name required"}, None
    
    try:
        # User credentials
        credential = DefaultAzureCredential()
        storage_client = StorageManagementClient(credential, subscription_id)

        # Obtener la clave de la cuenta de almacenamiento
        storage_account_keys = storage_client.storage_accounts.list_keys(resource_group_name, account_name)
        storage_account_key = storage_account_keys.keys[0].value

        BlobServiceClient(account_url=f"https://{account_name}.blob.core.windows.net", credential={"account_name": account_name, "account_key": storage_account_key})

        # Generate SAS token for the container
        sas_token = generate_container_sas(
            account_name=account_name,
            container_name=container_name,
            account_key=storage_account_key,
            permission=ContainerSasPermissions(read=True, write=True, delete=True, list=True),
            expiry=datetime.now(timezone.utc) + timedelta(hours=4)  # Set expiry time to 4 hours
        )
        
        sas_url = f"https://{account_name}.blob.core.windows.net/{container_name}?{sas_token}"
        
        pretty_response = {}                
        pretty_response["Success"] = {
                "sas_url" : sas_url
            }
            
        return True, sas_token, pretty_response
    
    except Exception as e:
        return False, {"Error" : e}, None


# Function to define the input fields required for the technique execution
def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Subscription ID", "id" : "subscription-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Resource Group Name", "id" : "resource-group-name-text-input", "type" : "text", "placeholder" : "rg-name", "element_type" : "dcc.Input"},
        {"title" : "Account Name", "id" : "account-name-text-input", "type" : "text", "placeholder" : "storageacctest", "element_type" : "dcc.Input"},
        {"title" : "Container Name", "id" : "container-name-text-input", "type" : "text", "placeholder" : "containertest", "element_type" : "dcc.Input"}
    ]

