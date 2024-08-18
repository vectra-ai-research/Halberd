'''
Module Name : List_Resources
Module Description : Attempts to list resources in the current selected subscription
'''

from azure.mgmt.resource import ResourceManagementClient

from core.AzureFunctions import GetCurrentSubscriptionAccessInfo, GetAzureAuthCredential

def TechniqueMain():
    try:
        default_credential = GetAzureAuthCredential()

        # retrieve subscription id
        current_sub_info = GetCurrentSubscriptionAccessInfo()
        subscription_id = current_sub_info.get("id")

        # create client
        resource_client = ResourceManagementClient(default_credential, subscription_id)

        # list resource groups
        group_list_object = resource_client.resource_groups.list()
        group_list = []

        try:
            # create pretty response
            pretty_response = {}
            for item in group_list_object:
                group_list.append(item)
                pretty_response[item.name] = item
            
            return True, group_list, pretty_response
        except:
            return True, group_list, group_list
        
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return []