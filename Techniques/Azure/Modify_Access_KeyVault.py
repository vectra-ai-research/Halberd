'''
Module Name : Modify_Access_KeyVault
Module Description : Loops through Key Vaults to check permissions and assigning necessary permissions to access the Key Vault. 
'''
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.keyvault.models import AccessPolicyEntry, VaultAccessPolicyParameters, Permissions
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters
from azure.mgmt.authorization import AuthorizationManagementClient

import requests
import uuid

def TechniqueMain(subscription_id):
    '''Function to manage access policies'''
    
    # input validation
    if subscription_id in ["", None]:
        return False, {"Error" : "Invalid input : Subscription ID required"}, None

    # User credentials
    credential = DefaultAzureCredential()
    client = KeyVaultManagementClient(credential, subscription_id)
    token = credential.get_token("https://graph.microsoft.com/.default").token
    headers = {'Authorization': f'Bearer {token}'}
    user_response = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers)
    tenant_response = requests.get('https://graph.microsoft.com/v1.0/organization', headers=headers)
    
    # get user id
    user = user_response.json()
    user_object_id = user['id']
    
    # get tenant id
    tenant = tenant_response.json()
    tenant_id = tenant['value'][0]['id']
    
    # Role definition ID for KeyVault Administrator
    role_definition_id = "00482a5a-887f-4fb3-b363-3b7fe8e74483"
    
    pretty_response = {"Success": {}}
    
    try:
        for vault in client.vaults.list():
            vault_name = vault.name
            resource_group_name = vault.id.split("/")[4]
            vault_messages = []
            
            try:
                # Check access to secrets and keys
                secret_client = SecretClient(vault_url=f"https://{vault_name}.vault.azure.net/", credential=credential)
                for secret in secret_client.list_properties_of_secrets():
                    secret.name

                key_client = KeyClient(vault_url=f"https://{vault_name}.vault.azure.net/", credential=credential)
                for key in key_client.list_properties_of_keys():
                    key.name
                vault_messages.append(f"Key Vault {vault_name} ready")

            except Exception as e:
                if "ForbiddenByPolicy" in str(e) or "AccessDenied" in str(e):
                    try:
                        # Assign access policy if access is denied
                        permissions = Permissions(keys=["get", "list"], secrets=["get", "list"], certificates=["get", "list"])
                        access_policy = AccessPolicyEntry(tenant_id=tenant_id, object_id=user_object_id, permissions=permissions)
                        vault = client.vaults.get(resource_group_name, vault_name)
                        vault.properties.access_policies.append(access_policy)
                        parameters = VaultAccessPolicyParameters(properties=vault.properties)
                        client.vaults.update_access_policy(resource_group_name, vault_name, "add", parameters)
                        vault_messages.append(f"Access policy added for {vault_name}")
                    except Exception as e:
                        vault_messages.append(f"Failed to add access policy for {vault_name}: {e}")
                        
                elif "ForbiddenByRbac" in str(e):
                    try:
                        # Assign role if access is forbidden by RBAC
                        auth_client = AuthorizationManagementClient(credential, subscription_id)
                        role_assignment_params = RoleAssignmentCreateParameters(
                            role_definition_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_definition_id}",
                            principal_id=user_object_id
                        )
                        auth_client.role_assignments.create(
                            scope=f"/subscriptions/{subscription_id}",
                            role_assignment_name=str(uuid.uuid4()),
                            parameters=role_assignment_params
                        )
                        vault_messages.append(f"KeyVault Administrator role assigned for {vault_name}")
                    except Exception as e:
                        vault_messages.append(f"Failed to add role for {vault_name}: {e}")
                
            pretty_response["Success"][vault_name] = vault_messages
   
        raw_response  = {}      
        
        return True, raw_response, pretty_response
    
    except Exception as e:
        return False, {"Error" : e}, None

# Function to define the input fields required for the technique execution
def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Subscription ID", "id" : "subscription-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"}
    ]