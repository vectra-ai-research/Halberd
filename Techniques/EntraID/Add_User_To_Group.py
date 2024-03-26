'''
Module Name : Add_User_To_Group
Module Description : Add an user to a group in Entra ID'''
from core.GraphFunctions import graph_post_request

def TechniqueMain(user_id, group_id):

    # input validation
    if user_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None
    if group_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    endpoint_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"
    data = {
        "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
    }

    try:
        raw_response = graph_post_request(url = endpoint_url, data = data)

        # add user to group operation successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Success"] = {
                    'Message' : "User added to group",
                    'Group' : group_id,
                    'User' : user_id
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
        
        # create account operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "User Object ID", "id" : "user-object-id-text-input", "type" : "text", "placeholder" : "eea797f8-7d94-5015-9977-64babe7d9507", "element_type" : "dcc.Input"},
        {"title" : "Target Group Object ID", "id" : "group-object-id-text-input", "type" : "text", "placeholder" : "05c6930b1-6c88-8024-8844-32babe7d9194", "element_type" : "dcc.Input"}
    ]