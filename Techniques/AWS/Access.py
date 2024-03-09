import boto3
import boto3.session

def TechniqueMain(aws_access_key_id, aws_secret_access_key, aws_region = None, session_token = None):
    
    # Remove any default session
    boto3.DEFAULT_SESSION = None

    try:
        # aws region defined
        if aws_region:
            new_session = boto3.session.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=aws_region)
        
        # use default aws region to create session
        else:
            # no session token defined
            if session_token in [None, ""]:
                new_session = boto3.session.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
            # use session token to create session
            else:
                new_session = boto3.session.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, aws_session_token = session_token)
                
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