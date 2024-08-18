'''
Module Name : Create_Resource_Group
Module Description : Attempts to create a new resource group in the current selected subscription
'''

from azure.mgmt.resource import ResourceManagementClient

from core.AzureFunctions import GetCurrentSubscriptionAccessInfo, GetAzureAuthCredential

def TechniqueMain(new_rg_name, new_rg_loc):

    # input validation
    if new_rg_name in ["", None]:
        return False, {"Error" : "Resource Group Name required"}, None
    if new_rg_loc in ["", None]:
        return False, {"Error" : "Resource Group Location required"}, None
    
    try:
        default_credential = GetAzureAuthCredential()

        # retrieve subscription id
        current_sub_info = GetCurrentSubscriptionAccessInfo()
        subscription_id = current_sub_info.get("id")

        # create client
        resource_client = ResourceManagementClient(default_credential, subscription_id)

        # resource group object
        rg_object = {
            "location": new_rg_loc
        }

        # create resource group
        new_rg = resource_client.resource_groups.create_or_update(
            new_rg_name, rg_object
        )

        try:
            # create pretty response
            pretty_response = {}
            pretty_response["Success"] = {
                "Message" : "New resource group created",
                "RG Name" : new_rg.name,
                "RG Location" : new_rg.location
            }

            return True, new_rg, pretty_response
        except:
            return True, new_rg, new_rg
    except Exception as e:
        return False, {"Error" : e}, None
    
def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "New Resource Group Name", "id" : "rg-name-text-input", "type" : "text", "placeholder" : "cool-tester-rg", "element_type" : "dcc.Input"},
        {"title" : "New Resource Group Location", "id" : "rg-location-text-input", "type" : "text", "placeholder" : "centralus", "element_type" : "dcc.Input"}
    ]