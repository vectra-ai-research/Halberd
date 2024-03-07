from core.GraphFunctions import graph_get_request

def ReadAllGraphPermissions():
    '''Ref: https://learn.microsoft.com/en-us/graph/permissions-reference'''

    endpoint_url = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?$select=id,appId,displayName,appRoles,oauth2PermissionScopes,resourceSpecificApplicationPermissions"
    graph_response = graph_get_request(url = endpoint_url)
    print(graph_response)
    return graph_response

def GetAllUserOwnedObjects(user_id):

    endpoint_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{user_id}/ownedObjects"

    graph_response = graph_get_request(url=endpoint_url)
    print(graph_response)
    return graph_response

def GetAllUsers():
    endpoint_url = "https://graph.microsoft.com/v1.0/users"

    all_users = graph_get_request(url=endpoint_url)

    return all_users

def GetUserInfo():
    endpoint_url = "https://graph.microsoft.com/v1.0/me"

    user_info = graph_get_request(url = endpoint_url)
    print(user_info)
    user_name = user_info['userPrincipalName']
    display_name = user_info['displayName']
    user_object_id = user_info['id']
    return user_name, display_name, user_object_id

'''Accessible groups'''
def ListJoinedTeams():
    try:
        endpoint_url = "https://graph.microsoft.com/v1.0/me/joinedTeams"

        joined_teams_list = graph_get_request(url = endpoint_url)
        
        output_list=[]
        for teams in joined_teams_list:
            output_list.append(teams['displayName'])

        return output_list
    except:
        return None

'''Associated Teams'''
def ListAssociatedTeams():
    endpoint_url = "https://graph.microsoft.com/v1.0/me/teamwork/associatedTeams"

    associated_teams_list = graph_get_request(url = endpoint_url)
    
    output_list=[]
    for teams in associated_teams_list:
        output_list.append(teams['displayName'])

    return output_list

'''Objects member of'''
def ListObjectsMemberOf():
    try:
        username,displayname, user_object_id = GetUserInfo()

        endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_object_id}/memberOf"

        member_objects_list = graph_get_request(url = endpoint_url)
        print(member_objects_list)

        group_list = []
        roles_list = []
        others_list = []
        for object in member_objects_list:
            if object["@odata.type"] == "#microsoft.graph.directoryRole":
                roles_list.append(object["displayName"])
            elif object["@odata.type"] == "#microsoft.graph.group":
                group_list.append(object["displayName"])
            else:
                others_list.append(object["displayName"])

        return group_list, roles_list, others_list
    except:
        return None

'''Objects transitive member of'''
def ListObjectsTransitiveMemberOf():
    try:
        username,displayname, user_object_id = GetUserInfo()

        endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_object_id}/transitiveMemberOf"

        transitive_member_objects_list = graph_get_request(url = endpoint_url)

        group_list = []
        roles_list = []
        others_list = []
        for object in transitive_member_objects_list:
            if object["@odata.type"] == "#microsoft.graph.directoryRole":
                roles_list.append(object["displayName"])
            elif object["@odata.type"] == "#microsoft.graph.group":
                group_list.append(object["displayName"])
            else:
                others_list.append(object["displayName"])

        return group_list, roles_list, others_list
    except:
        return None


'''Accessible applications'''



'''App role assignments'''
def ListAppRoleAssignments():
    try:
        username,displayname, user_object_id = GetUserInfo()
        endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_object_id}/appRoleAssignments"

        app_role_assignments_list = graph_get_request(url = endpoint_url)
        output_list = []

        for app_role in app_role_assignments_list:
            output_list.append(app_role['resourceDisplayName'])

        return output_list
    except:
        return None
'''Roles'''


'''Data - Sharepoint sites / Onedrive'''
def ListDrives():
    try:
        endpoint_url = "https://graph.microsoft.com/v1.0/me/drive"

        drives_list = graph_get_request(url = endpoint_url)

        output_list = []
        output_list.append(f"{drives_list['name']} : {drives_list['webUrl']}")

        return output_list
    except:
        return None