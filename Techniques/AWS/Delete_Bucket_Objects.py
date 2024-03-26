'''
Module Name: Delete_Bucket_Objects
Description: Delete an object or all objects in a specified S3 bucket
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/client/delete_object.html
'''
from core.AWSFunctions import CreateClient

def TechniqueMain(bucket_name, object_key_name, confirm_prompt = None):

    # input validation
    if bucket_name in [None, ""]:
        return False, {"Error" : "Invalid input"}, None

    # confirm deletion to avoid accidental execution by user
    if confirm_prompt != "[confirm delete]":
        return False, {"Error" : "Enter [confirm delete]"}, None

    # initialize boto3 s3 client
    my_client = CreateClient('s3')

    try:
        # list objects in bucket
        all_bucket_object_keys = []

        if object_key_name in [None, ""]:
            # s3 object enumeration to get all objects in bucket
            response = my_client.list_objects_v2(Bucket=bucket_name)
            all_bucket_objects = response['Contents']

            for object in all_bucket_objects:
                all_bucket_object_keys.append(object.get('Key'))

        # only add object specified to delete list
        else:
            all_bucket_object_keys.append(object_key_name)
    
    except Exception as e:
        # bucket enumeration failed
        return False, {"Error" : e}, None

    # initialize list to track deleted objects
    deleted_objects = []
    # initialize counter to track deleted objects
    object_delete_counter = 0
    delete_failed_counter = 0

    try:
        for object_key in all_bucket_object_keys:
            # delete objects
            try:
                raw_response = my_client.delete_object(
                    Bucket = bucket_name,
                    Key = object_key
                    )
                # object deleted successfully 
                if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                    # add object to deleted objects list
                    deleted_objects.append(object_key)
                    object_delete_counter += 1
                else:
                    # object deletion failed
                    raise Exception
            except:
                # do nothing - attempt to delete next object
                delete_failed_counter += 1

        pretty_response = {}
        pretty_response["Success"] = {
            "Message" : "S3 bucket objects deleted",
            "Number Of Successful Deletions" : object_delete_counter, 
            "Number Of Failed Deletions" : delete_failed_counter,
            "Deleted Objects" : str(deleted_objects)
        }

        # raw response same as pretty response
        raw_response = pretty_response
        return True, raw_response, pretty_response
    
    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Bucket Name", "id" : "bucket-text-input", "type" : "text", "placeholder" : "data-bucket", "element_type" : "dcc.Input"},
        {"title" : "Object Name to Delete (optional)", "id" : "object-text-input", "type" : "text", "placeholder" : "bucket-object-name", "element_type" : "dcc.Input"},
        {"title" : "Enter [confirm delete]", "id" : "confirm-text-input", "type" : "text", "placeholder" : "[confirm delete]", "element_type" : "dcc.Input"}
    ]