from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient

def TechniqueMain(subscription_id, resource_group_name, disk_name):
    '''Function to generate SAS token for a VM's Disk'''
    
    # input validation
    if subscription_id in ["", None]:
        return False, {"Error" : "Invalid input : Subscription ID required"}, None
    if resource_group_name in ["", None]:
        return False, {"Error" : "Invalid input : Resource Group Name required"}, None
    if disk_name in ["", None]:
        return False, {"Error" : "Invalid input : Disk Name required"}, None
    
    
    try:
        credential = DefaultAzureCredential()
        compute_client = ComputeManagementClient(credential, subscription_id)

        try:
            disk = compute_client.disks.get(resource_group_name, disk_name=disk_name)
            sas_token = compute_client.disks.begin_grant_access(
                resource_group_name=disk.id.split('/')[4],
                disk_name=disk_name,
                grant_access_data={
                    'access': 'Read',
                    'duration_in_seconds': 86400
                }
            ).result()
        except Exception as e:
            return False, {"Error" : e}, None

        if sas_token.access_sas:
            print("Successfully got a link. Link is active for 24 hours.")
            link_data = {
                "virtual_machine": disk.managed_by.split('/')[8],  
                "disk_name": disk_name,
                "link": sas_token.access_sas
            }
            pretty_response = {}                
            pretty_response["Success"] = {
                "sas_url" : link_data
            }
            return True, sas_token.access_sas, pretty_response
        else:
            return True, sas_token, None

    except Exception as e:
        return False, {"Error" : e}, None
    
# Function to define the input fields required for the technique execution
def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Subscription ID", "id" : "subscription-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Resource Group Name", "id" : "rg-name-text-input", "type" : "text", "placeholder" : "rg-test", "element_type" : "dcc.Input"},
        {"title" : "Disk Name", "id" : "disk-name-text-input", "type" : "text", "placeholder" : "disk0_098765", "element_type" : "dcc.Input"}
    ]
    
    
