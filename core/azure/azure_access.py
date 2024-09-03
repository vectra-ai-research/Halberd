import subprocess
import json
import sys
import shutil
import os
from azure.identity import AzureCliCredential, DefaultAzureCredential

class AzureAccess:
    """Azure access manager"""
    def __init__(self):
        self.az_command = check_azure_cli_install()

    def get_current_subscription_info(self):
        """Get current subscription info for connected account."""
        raw_response = subprocess.run([self.az_command, "account", "show"], capture_output=True)
        if raw_response.returncode == 0:
            output = raw_response.stdout
            return json.loads(output.decode('utf-8'))
        return None

    def get_account_available_subscriptions(self):
        """Get list of available subscriptions."""
        raw_response = subprocess.run([self.az_command, "account", "list"], capture_output=True)
        if raw_response.returncode == 0:
            output = raw_response.stdout
            return json.loads(output.decode('utf-8'))
        return None

    def set_active_subscription(self, subscription_id):
        """Set default subscription in environment to use."""
        raw_response = subprocess.run([self.az_command, "account", "set", "--subscription", subscription_id], capture_output=True)
        return True if raw_response.returncode == 0 else None

    @staticmethod
    def get_azure_auth_credential():
        """Get Azure authentication credential."""
        try:
            return AzureCliCredential()
        except:
            return DefaultAzureCredential()

    def execute_az_command(self, *args):
        """Execute an arbitrary Azure CLI command."""
        raw_response = subprocess.run([self.az_command, *args], capture_output=True)
        if raw_response.returncode == 0:
            output = raw_response.stdout
            try:
                return json.loads(output.decode('utf-8'))
            except json.JSONDecodeError:
                return output.decode('utf-8').strip()
        return None
    
def check_azure_cli_install():
    '''Function checks for installation of Azure cli on host'''
    
    if sys.platform.startswith('win'):
        # search in PATH
        az_cli_path = shutil.which("az")
        if az_cli_path:
            return az_cli_path
        
        # if not found in PATH, check in common installation paths on Windows
        common_win_paths = [
            r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin",
            r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin",
        ]
        for path in common_win_paths:
            az_cli_path = os.path.join(path, "az.cmd")
            if os.path.exists(az_cli_path):
                return az_cli_path
            
    else:
        # for non-windows systems, check if 'az' is in PATH
        if shutil.which("az"):
            return "az"
    
    # if az installation not found on host,return None
    return None