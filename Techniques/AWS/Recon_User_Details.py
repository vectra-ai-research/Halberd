'''
Module Name: Recon_User_Details
Module Description: Retrieve information about a user 
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/get_user.html
'''
from core.AWSFunctions import CreateClient

def TechniqueMain(user_name):
    # input validation
    if user_name in [None, ""]:
        return False, {"Error" : "Invalid input"}, None

    # initialize boto3 iam client
    my_client = CreateClient('iam')

    try:
        raw_response = my_client.get_user(UserName=user_name)
    
        try:
            # parse raw response => pretty response
            pretty_response = {}

            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                pretty_response["Success"] = {
                    'Username': raw_response.get('User', 'N/A').get('UserName','N/a'),
                    'User ID' : raw_response.get('User', 'N/A').get('UserId','N/A'),
                    'ARN' : raw_response.get('User', 'N/A').get('Arn','N/A'),
                    'Create Date' : raw_response.get('User', 'N/A').get('CreateDate','N/A'),
                    'Password Last Used' : raw_response.get('User', 'N/A').get('PasswordLastUsed','N/A'),
                    'PermissionsBoundary' : raw_response.get('User', 'N/A').get('PermissionsBoundary','N/A'),
                    'Tags' : raw_response.get('User', 'N/A').get('Tags','N/A')
                }

                return True, raw_response, pretty_response
            else:
                return False, {"Error" : raw_response}, None
        except:
            # return only raw response if pretty response fails
            return True, raw_response, None

    except Exception as e:
        return False, {"Error" : e}, None
    
def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Username", "id" : "username-text-input", "type" : "text", "placeholder" : "target_username", "element_type" : "dcc.Input"}
    ]