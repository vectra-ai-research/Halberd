from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.resource import ResourceManagementClient
from core.azure.azure_access import AzureAccess

@TechniqueRegistry.register
class AzureFindKeyVaults(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1552.006",
                technique_name="Credentials from Password Stores",
                tactics=["Credential Access"],
                sub_technique_name="Cloud Secrets Management Stores"
            ),
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT604",
                technique_name="Azure KeyVault Dumping",
                tactics=["Credential Access"],
                sub_technique_name=None
            )
        ]
        
        references = [
            TechniqueReference("Azure Key Vault Documentation", "https://learn.microsoft.com/en-us/azure/key-vault/general/overview")
        ]
        
        notes = [
            TechniqueNote("This technique is useful as part of a broader discovery strategy to identify potential sensitive credential stores"),
            TechniqueNote("Key Vaults often contain high-value targets like service credentials, certificates, and connection strings"),
            TechniqueNote("Consider following up with AzureDumpKeyVault technique to extract vault contents"),
            TechniqueNote("Check vault access policies and RBAC settings for potential access vectors")
        ]
        
        super().__init__(
            "Enumerate Key Vaults", 
            "Enumerates all Azure Key Vaults in the current subscription or specified resource group. Key Vaults are often used to store sensitive credentials, certificates, keys, and secrets that could provide access to other resources or services. This technique maps available Key Vaults, identifies their security configuration, and reveals potential targets for further exploitation. Information gathered includes Key Vault URIs, access policies, network configurations, RBAC settings, and managed identity assignments that might be leveraged for unauthorized access.",
            mitre_techniques,
            azure_trm_technique,
            references=references,
            notes=notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            resource_group_name: str = kwargs.get("resource_group_name", None)
            scan_all_subscriptions: bool = kwargs.get("scan_all_subscriptions", False)
            include_details: bool = kwargs.get("include_details", True)
            
            # Get credential and subscription info
            credential = AzureAccess.get_azure_auth_credential()
            current_sub_info = AzureAccess().get_current_subscription_info()
            subscription_id = current_sub_info.get("id")
            
            # Create clients
            keyvault_client = KeyVaultManagementClient(credential, subscription_id)
            resource_client = ResourceManagementClient(credential, subscription_id)
            
            subscriptions_to_scan = []
            
            # Determine which subscriptions to scan
            if scan_all_subscriptions:
                # Get all available subscriptions
                available_subs = AzureAccess().get_account_available_subscriptions()
                if available_subs:
                    subscriptions_to_scan = [sub.get("id") for sub in available_subs]
                else:
                    # Fallback to current subscription if can't get list
                    subscriptions_to_scan = [subscription_id]
            else:
                # Just use current subscription
                subscriptions_to_scan = [subscription_id]
            
            all_key_vaults = {}
            total_vaults_found = 0
            
            # Scan each subscription
            for sub_id in subscriptions_to_scan:
                subscription_name = None
                subscription_vaults = {}
                
                try:
                    # Create new client for this subscription
                    kv_client = KeyVaultManagementClient(credential, sub_id)
                    res_client = ResourceManagementClient(credential, sub_id)
                    
                    # Get subscription name
                    subscription_info = next((sub for sub in AzureAccess().get_account_available_subscriptions() 
                                            if sub.get("id") == sub_id), None)
                    subscription_name = subscription_info.get("name") if subscription_info else sub_id
                    
                    # Determine resource groups to scan
                    if resource_group_name:
                        resource_groups = [resource_group_name]
                    else:
                        resource_groups = [rg.name for rg in res_client.resource_groups.list()]
                    
                    # Scan each resource group
                    for rg in resource_groups:
                        rg_vaults = []
                        try:
                            # List vaults in this resource group
                            vaults = kv_client.vaults.list_by_resource_group(rg)
                            
                            # Process each vault
                            for vault in vaults:
                                vault_info = {
                                    "name": vault.name,
                                    "resource_group": rg,
                                    "location": vault.location,
                                    "uri": f"https://{vault.name}.vault.azure.net/",
                                    "tenant_id": vault.properties.tenant_id,
                                    "sku": vault.properties.sku.name,
                                    "enabled_for_deployment": vault.properties.enabled_for_deployment,
                                    "enabled_for_disk_encryption": vault.properties.enabled_for_disk_encryption,
                                    "enabled_for_template_deployment": vault.properties.enabled_for_template_deployment,
                                    "soft_delete_enabled": vault.properties.enable_soft_delete,
                                    "purge_protection_enabled": vault.properties.enable_purge_protection
                                }
                                
                                # Add detailed information if requested
                                if include_details:
                                    # Get network configuration
                                    network_acls = vault.properties.network_acls
                                    if network_acls:
                                        vault_info["network_acls"] = {
                                            "default_action": network_acls.default_action,
                                            "bypass": network_acls.bypass,
                                            "ip_rules": network_acls.ip_rules,
                                            "virtual_network_rules": network_acls.virtual_network_rules
                                        }
                                    else:
                                        vault_info["network_acls"] = {"default_action": "Allow"}
                                    
                                    # Get access policies
                                    access_policies = []
                                    if vault.properties.access_policies:
                                        for policy in vault.properties.access_policies:
                                            access_policies.append({
                                                "tenant_id": policy.tenant_id,
                                                "object_id": policy.object_id,
                                                "permissions": {
                                                    "keys": policy.permissions.keys if policy.permissions.keys else [],
                                                    "secrets": policy.permissions.secrets if policy.permissions.secrets else [],
                                                    "certificates": policy.permissions.certificates if policy.permissions.certificates else []
                                                }
                                            })
                                    
                                    vault_info["access_policies"] = access_policies
                                    
                                    # Get private endpoint connections if available
                                    if hasattr(vault.properties, 'private_endpoint_connections') and vault.properties.private_endpoint_connections:
                                        vault_info["private_endpoints"] = [
                                            {
                                                "id": pe.id,
                                                "name": pe.name,
                                                "status": pe.properties.private_link_service_connection_state.status
                                            } for pe in vault.properties.private_endpoint_connections
                                        ]
                                
                                rg_vaults.append(vault_info)
                                total_vaults_found += 1
                                
                            if rg_vaults:
                                subscription_vaults[rg] = rg_vaults
                                
                        except Exception as rg_error:
                            # Continue with next resource group if one fails
                            continue
                    
                    if subscription_vaults:
                        all_key_vaults[subscription_name] = subscription_vaults
                        
                except Exception as sub_error:
                    # Continue with next subscription if one fails
                    continue
            
            if total_vaults_found > 0:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully found {total_vaults_found} Key Vaults across {len(all_key_vaults)} subscriptions",
                    "value": all_key_vaults
                }
            else:
                return ExecutionStatus.SUCCESS, {
                    "message": "No Key Vaults found in the specified scope",
                    "value": {}
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate Key Vaults"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "resource_group_name": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Filter : Resource Group Name",
                "input_field_type": "text"
            },
            "scan_all_subscriptions": {
                "type": "bool",
                "required": False,
                "default": False,
                "name": "Scan All Accessible Subscriptions",
                "input_field_type": "bool"
            },
            "include_details": {
                "type": "bool",
                "required": False,
                "default": True,
                "name": "Include Full Vault Details",
                "input_field_type": "bool"
            }
        }