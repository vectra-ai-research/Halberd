import subprocess
import json

# get current subscription info for connected account 
def GetCurrentSubscriptionAccessInfo():
    raw_response = subprocess.run(["az", "account", "show"], capture_output=True)
    if raw_response.returncode == 0:
        output = raw_response.stdout
        struc_output = json.loads(output.decode('utf-8'))
        
        return struc_output
    else:
        return None

# get list of available subscriptions
def GetAccountSubscriptionList():
    raw_response = subprocess.run(["az", "account", "list"], capture_output=True)
    if raw_response.returncode == 0:
        output = raw_response.stdout
        struc_output = json.loads(output.decode('utf-8'))
        
        return struc_output
    else:
        return None
    
# set default subscription in environment to use 
def SetDefaultSubscription(subscription_id):
    raw_response = subprocess.run(["az", "account", "set", "--subscription", subscription_id], capture_output=True)

    if raw_response.returncode == 0:
        # returns no output on success
        return True
    else:
        return None