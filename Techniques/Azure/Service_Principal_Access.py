'''
Module Name : Service_Principal_Access
Module Description : Attempts to establish access using a service principal client ID and secret
'''
import subprocess
import json
from core.Functions import CheckAzureCLIInstall

def TechniqueMain(app_id, app_secret, tenant_id, allow_no_sub_login=False):

    # get az full execution path
    az_command = CheckAzureCLIInstall()

    try:
        if allow_no_sub_login == False:
            raw_response = subprocess.run([az_command, "login", "--service-principal", "-u", app_id, f"-p={app_secret}", "--tenant", tenant_id], capture_output=True)
        else:
            raw_response = subprocess.run([az_command, "login", "--service-principal", "-u", app_id, f"-p={app_secret}", "--tenant", tenant_id, "--allow-no-subscriptions"], capture_output=True)

        output = raw_response.stdout
        struc_output = json.loads(output.decode('utf-8'))
        
        if raw_response.returncode == 0:
            pretty_response = {}
            for subscription in struc_output:
                pretty_response[subscription.get("id", "N/A")] = {
                    "Subscription Name" : subscription.get("name", "N/A"),
                    "Subscription ID" : subscription.get("id", "N/A"),
                    "Home Tenant Id" : subscription.get("homeTenantId", "N/A"),
                    "State" : subscription.get("state", "N/A"),
                    "Identity (User/App)" : subscription.get("user", "N/A").get("name","N/A"),
                    "Identity Type" : subscription.get("user", "N/A").get("type","N/A"),
                }
            return True, struc_output, pretty_response 
        else:
            return False, struc_output, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Client ID", "id" : "client-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Client Secret", "id" : "client-secret-text-input", "type" : "password", "placeholder" : "something_long&difficu1t", "element_type" : "dcc.Input"},
        {"title" : "Tenant ID", "id" : "tenant-id-text-input", "type" : "text", "placeholder" : "1234-5678-9098-7654-3210", "element_type" : "dcc.Input"},
        {"title" : "Attempt Login Without Subscription", "id" : "no-sub-login-boolean-switch", "type" : "text", "placeholder" : "null", "element_type" : "daq.BooleanSwitch"}
    ]