'''
Module Name : Remove_Account
Description : Delete an user account in Entra ID
'''
from core.GraphFunctions import graph_delete_request

def TechniqueMain(user_id):
    endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"

    # input validation
    if user_id in [None, ""]:
        return False, {"Error" : "Invalid Technique Input"}, None

    try:
        # delete user account
        raw_response = graph_delete_request(url = endpoint_url)

        # delete operation successfull
        if 200 <= raw_response.status_code < 300:
            # parse raw response => pretty response
            try:
                # create pretty response
                pretty_response = {}

                pretty_response["Account Deleted"] = {
                    'Deleted Account' : user_id,
                    'Response Code' : raw_response.status_code
                }
                return True, raw_response, pretty_response
            except:
                # return only raw response if pretty response fails
                return True, raw_response, None
        
        # delete operation failed
        else:
            return False, {"Error" : {"Response Status" : raw_response.status_code, "Code" : raw_response.json().get('error').get('code', 'N/A'), "Message" : raw_response.json().get('error').get('message', 'N/A')}}, None
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''Returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Account UPN", "id" : "remove-account-access-text-input", "type" : "text", "placeholder" : "user@domain.com", "element_type" : "dcc.Input"}
    ]