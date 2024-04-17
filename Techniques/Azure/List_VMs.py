'''
Module Name : List_VMs
Module Description : Attempts to list VMs in the currrent selected subscription. Returns VM name, its resource group and the vm location.
'''

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from core.AzureFunctions import GetCurrentSubscriptionAccessInfo

def TechniqueMain():
    try:
        default_credential = DefaultAzureCredential()

        # retrieve subscription id
        current_sub_info = GetCurrentSubscriptionAccessInfo()
        subscription_id = current_sub_info.get("id")

        # create client
        compute_client = ComputeManagementClient(default_credential, subscription_id)
        
        # list vms
        vm_list = compute_client.virtual_machines.list_all()

        try:
            # create pretty response
            pretty_response = {}

            for vm in vm_list:
                pretty_response[vm.name] = {
                    "Resource Group" : vm.id,
                    "VM Location" : vm.location
                }

            return True, vm_list, pretty_response
        except:
            return True, vm_list, vm_list
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return []