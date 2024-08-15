'''
Module Name : Discover_Applications
Description : Recon applications available in microsoft tenant
'''
from core.GraphFunctions import graph_get_request

def TechniqueMain(permission_id = None):
    endpoint_url = "https://graph.microsoft.com/v1.0/applications/"

    try:
        # recon applications
        raw_response = graph_get_request(url = endpoint_url)

        if 'error' in raw_response:
            return False, {"Error" : raw_response.get('error').get('message', 'N/A')}, None

        # create pretty response
        pretty_response = {}
        
        try:
            # parse raw response => pretty response
            for app in raw_response:
                if permission_id:
                    # enumerate through apps to find app with the associated permission
                    required_resource_access = app.get('requiredResourceAccess', [])
                    for resource in required_resource_access:
                        resource_accesses = resource.get('resourceAccess', [])
                        for access in resource_accesses:
                            if access.get('id') == permission_id:
                                pretty_response[app['id']] = {
                                    'Display Name' : app.get('displayName', 'N/A'),
                                    'Id' : app.get('id', 'N/A'),
                                    'App Id' : app.get('appId', 'N/A'),
                                    'Description' : app.get('description', 'N/A'),
                                    'App Roles' : app.get('appRoles', 'N/A'),
                                    'Password Credentials' : app.get('passwordCredentials', 'N/A'),
                                    'Required Resource Access' : app.get('requiredResourceAccess', 'N/A')
                                }
                                break
                else:
                    pretty_response[app['id']] = {
                        'Display Name' : app.get('displayName', 'N/A'),
                        'Id' : app.get('id', 'N/A'),
                        'App Id' : app.get('appId', 'N/A'),
                        'Description' : app.get('description', 'N/A'),
                        'App Roles' : app.get('appRoles', 'N/A'),
                        'Password Credentials' : app.get('passwordCredentials', 'N/A'),
                        'Required Resource Access' : app.get('requiredResourceAccess', 'N/A')
                    }

            return True, raw_response, pretty_response
        except:
            # return only raw response if pretty response fails
            return True, raw_response, None
        
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Permission Name or ID (Optional)", "id" : "entra-app-permission-text-input", "type" : "text", "placeholder" : "Mail.ReadWrite", "element_type" : "dcc.Input"}
    ]