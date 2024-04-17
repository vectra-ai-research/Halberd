'''
Module Name : Recon_Assigned_Roles
Module Description : Attempts to list role assignments in selected subscription
'''

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from core.AzureFunctions import GetCurrentSubscriptionAccessInfo

def TechniqueMain():
    try:
        default_credential = DefaultAzureCredential()

        # retrieve subscription id
        current_sub_info = GetCurrentSubscriptionAccessInfo()
        subscription_id = current_sub_info.get("id")

        # create client
        mgmt_client = AuthorizationManagementClient(default_credential, subscription_id)

        # list role assignments
        role_assignments = mgmt_client.role_assignments.list_for_subscription()
        
        try:
            # create pretty response
            pretty_response = {}
            for assignment in role_assignments:
                pretty_response[assignment.id] = {
                    "Role Assignment Name" : assignment.name,
                    "Role Definition ID" : assignment.role_definition_id,
                    "Principal ID" : assignment.principal_id,
                    "Principal Type" : assignment.principal_type,
                    "Condition" : assignment.condition,
                    "Type" : assignment.type
                }
            return True, role_assignments, pretty_response
        except:
            return True, role_assignments, role_assignments
    except Exception as e:
        return False, {"Error" : e}, None
    
def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return []