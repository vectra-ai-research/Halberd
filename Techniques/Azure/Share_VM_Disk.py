'''
Module Name : Share_VM_Disk
Module Description : Generate Shared Access Signatures (SAS) URIs specifically for disks of virtual machines in Azure.
'''

from azure.mgmt.compute import ComputeManagementClient
 
from core.AzureFunctions import GetAzureAuthCredential, GetCurrentSubscriptionAccessInfo

def TechniqueMain(subscription_id, resource_group_name, vm_name):
    '''Function to generate SAS token for VM disks'''
    
    # input validation
    if resource_group_name in ["", None]:
        return False, {"Error" : "Invalid input : Resource Group Name required"}, None
    if vm_name in ["", None]:
        return False, {"Error" : "Invalid input : VM Name required"}, None
    
    if subscription_id in ["", None]:
        # retrieve default set subscription id
        current_sub_info = GetCurrentSubscriptionAccessInfo()
        subscription_id = current_sub_info.get("id")
    
    try:
        credential = GetAzureAuthCredential()
        compute_client = ComputeManagementClient(credential, subscription_id)

        try:
            # Get the virtual machine
            vm = compute_client.virtual_machines.get(resource_group_name, vm_name)
            
            # Check the status of the VM
            instance_view = compute_client.virtual_machines.instance_view(resource_group_name, vm_name)
            vm_status = next((s.code for s in instance_view.statuses if s.code.startswith('PowerState/')), None)
            try:
                if vm_status != 'PowerState/deallocated':
                    print(f"VM {vm_name} is not stopped. Current state: {vm_status}. Stopping the VM...")
                    compute_client.virtual_machines.begin_deallocate(resource_group_name, vm_name).result()
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
                    disk_resource = compute_client.disks.get(resource_group_name, disk_name=os_disk.name)
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
                    disk_resource = compute_client.disks.get(resource_group_name, disk_name=data_disk.name)
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
                pretty_response = {"Success": sas_tokens}
                return True, sas_tokens, pretty_response
            else:
                return False, {"Error": "No SAS tokens generated"}, None

        except Exception as e:
            return False, {"Error" : e}, None

    except Exception as e:
        return False, {"Error" : e}, None

# Function to define the input fields required for the technique execution
def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Subscription ID (Optional)", "id" : "subscription-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Resource Group Name", "id" : "rg-name-text-input", "type" : "text", "placeholder" : "rg-test", "element_type" : "dcc.Input"},
        {"title" : "VM Name", "id" : "vm-name-text-input", "type" : "text", "placeholder" : "vm-name", "element_type" : "dcc.Input"}
    ]

