'''
Module Name: Delete_S3_Bucket
Description: Delete a S3 bucket
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/delete_bucket.html
'''
from core.AWSFunctions import CreateClient

def TechniqueMain(bucket_name, confirm_prompt = None):

    # input validation
    if bucket_name in [None, ""]:
        return False, {"Error" : "Invalid input"}, None

    # confirm deletion to avoid accidental execution by user
    if confirm_prompt != "[confirm delete]":
        return False, {"Error" : "Enter [confirm delete]"}, None

    # initialize boto3 s3 client
    my_client = CreateClient('s3')

    try:
        # delete bucket 
        raw_response = my_client.delete_bucket(
            Bucket = bucket_name
            )
        if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
            try:
                # parse raw response => pretty response
                pretty_response = {}
                pretty_response["Success"] = {
                    "Bucket Name" : bucket_name,
                    "Message" : "Bucket deleted"
                }
                return True, raw_response, pretty_response
            except:
                return True, raw_response, None
        else:
            return False, {"Error" : raw_response}, None
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Bucket Name", "id" : "bucket-text-input", "type" : "text", "placeholder" : "data-bucket", "element_type" : "dcc.Input"},
        {"title" : "Enter [confirm delete]", "id" : "confirm-text-input", "type" : "text", "placeholder" : "[confirm delete]", "element_type" : "dcc.Input"}
    ]