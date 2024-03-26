'''
Module Name: Delete_DynamoDB_Table
Description: Delete a table in dynamodb
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client/delete_table.html
'''
from core.AWSFunctions import CreateClient, valid_aws_regions

def TechniqueMain(table_name, region_name = None, confirm_prompt = None):
    # input validation
    if table_name in [None, ""]:
        return False, {"Error" : "Invalid input"}, None

    # confirm deletion to avoid accidental execution by user
    if confirm_prompt != "[confirm delete]":
        return False, {"Error" : "Enter [confirm delete]"}, None

    # set default region
    if region_name in [None, ""]:
        region_name = "us-east-1"
    
    # validate user input for region
    if region_name not in valid_aws_regions:
        return False, {"Error" : "Invalid Input: Invalid Region Name"}, None

    # initialize boto3 dynamodb client
    my_client = CreateClient('dynamodb', region_name = region_name)

    try:
        # delete table 
        raw_response = my_client.delete_table(
            TableName = table_name
            )
            
        # deletion successful
        if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
            try:
                # parse raw response => pretty response
                pretty_response = {}
                pretty_response["Success"] = {
                    "Message" : "Table deletion successful",
                    "Table Name" : raw_response.get('TableDescription','N/A').get('TableName','N/A'),
                    "Table Size in Bytes" : raw_response.get('TableDescription','N/A').get('TableSizeBytes','N/A'),
                    "Item Count" : raw_response.get('TableDescription','N/A').get('ItemCount','N/A'),
                    "Table ARN" : raw_response.get('TableDescription','N/A').get('TableArn','N/A')
                }
                return True, raw_response, pretty_response
            except:
                return True, raw_response, None
        else:
            # deletion failed
            return False, {"Error" : raw_response}, None

    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Table Name", "id" : "table-name-text-input", "type" : "text", "placeholder" : "data-bucket", "element_type" : "dcc.Input"},
        {"title" : "Table Region Name (Optional)", "id" : "region-name-text-input", "type" : "text", "placeholder" : "us-east-1", "element_type" : "dcc.Input"},
        {"title" : "Enter [confirm delete]", "id" : "confirm-text-input", "type" : "text", "placeholder" : "[confirm delete]", "element_type" : "dcc.Input"}
    ]