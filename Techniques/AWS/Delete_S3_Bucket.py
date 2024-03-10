'''
Module Name: Delete_S3_Bucket.py
Description: Delete a S3 bucket
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/delete_bucket.html
'''
from core.AWSFunctions import CreateClient
def TechniqueMain(bucket_name, confirm_prompt = None):

    # confirm deletion to avoid accidental execution by user
    if confirm_prompt != "[confirm delete]":
        return "Aborted : Enter [confirm delete]"

    # initialize boto3 s3 client
    my_client = CreateClient('s3')

    # list objects in bucket
    try:
        response = my_client.delete_object(
            Bucket = bucket_name
            )

    except Exception as e:
        return f"Error: {e}"

    try:
        # delete bucket 
        response = my_client.delete_bucket(
            Bucket = bucket_name
            )
        print(response)

    except Exception as e:
        return f"Error: {e}"

    return {"Bucket Deleted" : bucket_name}

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Bucket Name", "id" : "bucket-text-input", "type" : "text", "placeholder" : "data-bucket", "element_type" : "dcc.Input"},
        {"title" : "Enter [confirm delete]", "id" : "confirm-text-input", "type" : "text", "placeholder" : "[confirm delete]", "element_type" : "dcc.Input"}
    ]