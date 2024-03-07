import boto3
import boto3.session

def TechniqueMain(aws_access_key_id, aws_secret_access_key, aws_region = None):
    boto3.DEFAULT_SESSION = None
    try:
        if aws_region:
            new_session = boto3.session.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=aws_region)
        else:
            new_session = boto3.session.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

        sts = new_session.client('sts')
        caller_info = sts.get_caller_identity()

        #set as default session to use
        boto3.DEFAULT_SESSION = new_session

        return caller_info
    except Exception as e:
        return f"Failed : {e}"


def TechniqueInputSrc() -> dict:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Acccess Key ID", "id" : "s3-client-text-input", "type" : "text", "placeholder" : "Key ID", "element_type" : "dcc.Input"},
        {"title" : "Secret Access Key", "id" : "s3-client-text-input", "type" : "text", "placeholder" : "Key Secret", "element_type" : "dcc.Input"},
        {"title" : "Region", "id" : "s3-client-text-input", "type" : "text", "placeholder" : "(Optional) us-west-1", "element_type" : "dcc.Input"}
    ]