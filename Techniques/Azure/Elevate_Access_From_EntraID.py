'''
Module Name : Elevate_Access_From_EntraID
Module Description : Attempts to enable the configuration in Azure Entra ID that grants "User Access Administrator" role to a global admin in Entra ID 
Ref: # ref: https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin?tabs=azure-cli#step-1-elevate-access-for-a-global-administrator-2
'''

import subprocess

from core.Functions import CheckAzureCLIInstall

def TechniqueMain():
    try:
        # get az full execution path
        az_command = CheckAzureCLIInstall()
        if az_command:

            raw_response = subprocess.run([az_command, "rest", "--method", "post", "--url", "/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"], capture_output=True)

            if raw_response.returncode == 0:
                # successful operation has no response

                pretty_response = {}
                pretty_response["Success"] = {
                    "Message" : "Permission Granted",
                    "Role" : "User Access Administrator",
                    "Scope" : "/ (root)"
                }

                raw_response = pretty_response
                return True, raw_response, pretty_response 
            
            else:
                return True, raw_response, None
        else:
            return False, {"Error" : "Azure CLI installation not found on host"}, None
    
    except Exception as e:
        return False, {"Error" : e}, None
    
def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return []