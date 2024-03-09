'''
Module Name: List_Bucket_Objects.py
Description: List all objects in a specified S3 bucket
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/list_objects_v2.html
'''
from core.AWSFunctions import CreateClient
def TechniqueMain(bucketName):

    # initialize boto3 s3 client
    my_client = CreateClient('s3')

    # list objects in bucket
    try:
        response = my_client.list_objects_v2(Bucket=bucketName)

    except Exception as e:
        return f"Error: {e}"

    bucket_objects = response['Contents']

    bucket_object_info = {}

    for object in bucket_objects:

        bucket_object_info[object.get('Key', 'N/A')] = {
            'Object Key': object.get('Key', 'N/A'),
            'Last Modified' : object.get('LastModified', 'N/A'),
            'Size' : object.get('Size', 'N/A'),
            'Owner' : object.get('Owner', 'N/A')
        }

    return bucket_object_info

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Bucket Name", "id" : "bucket-text-input", "type" : "text", "placeholder" : "data-bucket", "element_type" : "dcc.Input"}
    ]