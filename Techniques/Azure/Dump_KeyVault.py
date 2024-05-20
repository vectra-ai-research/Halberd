from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from base64 import urlsafe_b64encode, urlsafe_b64decode

import jwt
import base64
import os



def TechniqueMain(subscription_id):
    '''Function to retrieve Key Vault data'''
    
    # Initialize Azure credentials
    credential = DefaultAzureCredential()
    
    # Initialize a dictionary to store Key Vault data
    key_vault_data = {}
    
    
        
    # Initialize KeyVaultManagementClient to manage Key Vaults
    client = KeyVaultManagementClient(credential, subscription_id)
    
    try:
        for vault in client.vaults.list():
            vault_name = vault.name
            resource_group_name = vault.id.split("/")[4]
            print(f"Dumping {vault_name}")
            
            # Initialize lists to store secrets, keys, and certificates for this vault
            secrets_list = []
            keys_list = []
            certificates_list = []
            message = []
               
            try:
                # Initialize SecretClient to access secrets in the Key Vault
                secret_client = SecretClient(vault_url=f"https://{vault_name}.vault.azure.net/", credential=credential)

                # Retrieve the list of secrets in the Key Vault
                secrets = secret_client.list_properties_of_secrets()
                # Iterate through each secret in the Key Vault
                for secret in secrets:
                    secret_name = secret.name
                    print(f"Getting Secret value for the {secret_name} Secret")

                    # Retrieve the secret value
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

                    # Append secret data to the list
                    if secret_type == "application/x-pkcs12":
                        certificates_list.append({
                            "certificate_name": secret_name,
                            "certificate_value": secret_value_text
                        })
                    else:
                        secrets_list.append({
                            "secret_name": secret_name,
                            "secret_value": secret_value_text
                        })

            except Exception as e:
                if "ForbiddenByPolicy" in str(e):
                    message.append("Error access secrets: : Access Policy required for Secrets")
                elif "ForbiddenByRbac" in str(e):
                    message.append("You do not have access to this Key Vault: RBAC required")
                elif "AccessDenied" in str(e):
                    message.append("You do not have access to this Key Vault: Access Policy required")
                    
                    

            try:
                # Initialize KeyClient to access keys in the Key Vault
                key_client = KeyClient(vault_url=f"https://{vault_name}.vault.azure.net/", credential=credential)

                # Retrieve the list of keys in the Key Vault
                keys = key_client.list_properties_of_keys()

                # Iterate through each key in the Key Vault
                for key in keys:
                    key_name = key.name
                    print(f"Getting Key value for the {key_name} Key")

                    # Retrieve the key data
                    key_data = key_client.get_key(key_name)
                    key_type = key_data.key_type
                    key_value = key_data.key.n
                    key_data_text = key_value

                    # Convert RSA public key to PEM format
                    if key_type == "RSA":
                        usable_jwk = {}
                        for k in vars(key_data.key):
                            value = vars(key_data.key)[k]
                            if value:
                                usable_jwk[k] = urlsafe_b64encode(value) if isinstance(value, bytes) else value

                        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(usable_jwk)
                        public_pem = public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        key_data_text = public_pem
                    
                    # Convert EC public key to PEM format
                    if key_type == "EC":
                        usable_jwk = {}
                        for k in vars(key_data.key):
                            value = vars(key_data.key)[k]
                            if value:
                                usable_jwk[k] = urlsafe_b64encode(value).decode('utf-8') if isinstance(value, bytes) else value

                        x = usable_jwk.get('x')
                        y = usable_jwk.get('y')
                        curve = usable_jwk.get('crv')
                        
                        if not (x and y and curve):
                            raise ValueError("Invalid JWK data for EC key")

                        try:
                            x_bytes = urlsafe_b64decode(x + '==')
                            y_bytes = urlsafe_b64decode(y + '==')

                            if curve == 'P-256':
                                curve = ec.SECP256R1()
                            elif curve == 'P-384':
                                curve = ec.SECP384R1()
                            elif curve == 'P-521':
                                curve = ec.SECP521R1()
                            else:
                                raise ValueError("Unsupported curve: {}".format(curve))

                            public_key = ec.EllipticCurvePublicNumbers(
                                int.from_bytes(x_bytes, 'big'),
                                int.from_bytes(y_bytes, 'big'),
                                curve
                            ).public_key()

                            public_pem = public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )

                            key_data_text = public_pem.decode('utf-8')
                        except Exception as e:
                            print(f"Error processing EC key: {e}")
                            key_data_text = None

                    # Append key data to the list
                    keys_list.append({
                        "key_name": key_name,
                        "key_value": f'{key_data_text}'
                    })

            except Exception as e:
                if "ForbiddenByPolicy" in str(e):
                    message.append("Error access keys: : Access Policy required for Keys and Certificates")
                elif "ForbiddenByRbac" in str(e):
                    pass
                    
        
            # Add certificates, keys, and secrets lists to the vault data dictionary
            key_vault_data[vault_name] = {
                "secrets": secrets_list,
                "keys": keys_list,
                "certificates": certificates_list,
                "message": message
            }


        return key_vault_data
    
    except Exception as e:
        return {"error": str(e)}
        

# Function to define the input fields required for the technique execution

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''

    return [
        {"title" : "subscription_id", "id" : "subscription-id-text-input", "type" : "text", "placeholder" : "12345678-1234-1234-1234-123456789012", "element_type" : "dcc.Input"},
    ]


