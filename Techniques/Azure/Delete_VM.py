'''
Module Name : Delete_VM
Module Description : Attempts to generate a request to delete a specific Azure VM within a resource group
'''

from azure.mgmt.compute import ComputeManagementClient

from core.AzureFunctions import GetCurrentSubscriptionAccessInfo, GetAzureAuthCredential

def TechniqueMain(vm_name, rg_name):

    # input validation
    if vm_name in ["", None]:
        return False, {"Error" : "VM Name required"}, None
    if rg_name in ["", None]:
        return False, {"Error" : "Resource Group Name required"}, None
    
    try:
        default_credential = GetAzureAuthCredential()

        # retrieve subscription id
        current_sub_info = GetCurrentSubscriptionAccessInfo()
        subscription_id = current_sub_info.get("id")

        # create client
        compute_client = ComputeManagementClient(default_credential, subscription_id)
        
        # attremp delete vm request
        vm_delete = compute_client.virtual_machines.delete(rg_name, vm_name)

        try:
            # create pretty response
            pretty_response = {}

            
            pretty_response["Success"] = {
                "VM" : vm_name,
                "Resource Group" : rg_name
            }

            return True, vm_delete, pretty_response
        except:
            return True, vm_delete, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "VM Name", "id" : "vm-name-text-input", "type" : "text", "placeholder" : "imp-vm-797", "element_type" : "dcc.Input"},
        {"title" : "Resource Group Name", "id" : "rg-name-text-input", "type" : "password", "placeholder" : "rg-1x1", "element_type" : "dcc.Input"}
    ]