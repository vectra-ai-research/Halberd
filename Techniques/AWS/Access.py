'''
Module Name: Access
Description: Establish aws session to create service clients and resources
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html
'''
import boto3
import boto3.session

def TechniqueMain(aws_access_key_id, aws_secret_access_key, aws_region = None, session_token = None):
    
    # Remove any default session
    boto3.DEFAULT_SESSION = None

    try:
        # use default aws region to create session
        if aws_region in [None, ""]:
            # no session token
            if session_token in [None, ""]:
                new_session = boto3.session.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            # use supplied session token to create session
            else:
                new_session = boto3.session.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, aws_session_token = session_token)
        
        # use supplied aws region
        else:
            # no session token
            if session_token in [None, ""]:
                new_session = boto3.session.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=aws_region)
            # use supplied session token to create session
            else:
                new_session = boto3.session.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=aws_region, aws_session_token = session_token)
            
                
        # current session info
        sts = new_session.client('sts')
        caller_info = sts.get_caller_identity()

        session_info = {
            'User ID' : caller_info.get('UserId', 'N/A'),
            'Account' : caller_info.get('Account', 'N/A'),
            'ARN' : caller_info.get('Arn', 'N/A')
        }

        # set new session as default session to use
        boto3.DEFAULT_SESSION = new_session

        return session_info
        
    except Exception as e:
        return f"Failed : {e}"


def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Acccess Key ID", "id" : "key-text-input", "type" : "text", "placeholder" : "Key ID", "element_type" : "dcc.Input"},
        {"title" : "Secret Access Key", "id" : "secret-text-input", "type" : "text", "placeholder" : "Key Secret", "element_type" : "dcc.Input"},
        {"title" : "Region (Optional)", "id" : "region-text-input", "type" : "text", "placeholder" : "us-east-1", "element_type" : "dcc.Input"},
        {"title" : "Session Token (Optional)", "id" : "session-token-text-input", "type" : "text", "placeholder" : "dasdhashdjasdj-t0lk3n", "element_type" : "dcc.Input"}
    ]