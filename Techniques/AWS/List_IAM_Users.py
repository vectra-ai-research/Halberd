'''
Module Name: List_IAM_Users
Module Description: List IAM users in aws account
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/client/list_users.html
'''
from core.AWSFunctions import CreateClient

def TechniqueMain(path_prefix = None):

    # initialize boto3 iam client
    my_client = CreateClient('iam')

    try:
        if path_prefix in [None, ""]:
            # list users in aws account
            raw_response = my_client.list_users()
        else:
            # list users in aws account with path prefix
            raw_response = my_client.list_users(
                PathPrefix = path_prefix
            )

        try:
            # parse raw response => pretty response
            pretty_response = {}
            all_users = raw_response['Users']
            for user in all_users:
                # all_user_output[user['UserId']] = user
                pretty_response[user['UserId']]= {
                    'Username' : user.get('UserName','N/A'),
                    'User Id' : user.get('UserId','N/A'),
                    'ARN' : user.get('Arn','N/A'),
                    'Creation Date' : user.get('CreateDate','N/A'),
                    'Path' : user.get('Path','N/A')
                }
            return True, raw_response, pretty_response
        except:
            # return only raw response if pretty response fails
            return True, raw_response, None

    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "User Path Prefix (optional)", "id" : "path-prefix-text-input", "type" : "text", "placeholder" : "/app_xyz/comp_123", "element_type" : "dcc.Input"},
    ]