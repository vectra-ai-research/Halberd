'''
Module Name: Delete_DynamoDB_Table.py
Description: Delete a table in dynamodb
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client/delete_table.html
'''
from core.AWSFunctions import CreateClient, valid_aws_regions
def TechniqueMain(table_name, region_name = None, confirm_prompt = None):

    # confirm deletion to avoid accidental execution by user
    if confirm_prompt != "[confirm delete]":
        return "Aborted : Enter [confirm delete]"

    # initialize boto3 dynamodb client
    # set default region
    if region_name in [None, ""]:
        region_name = "us-east-1"
    
    # validate user input for region
    if region_name not in valid_aws_regions:
        return "Invalid Input: Invalid Region Name"

    # initialize boto3 dynamodb client
    my_client = CreateClient('dynamodb', region_name = region_name)

    try:
        # delete table 
        response = my_client.delete_table(
            TableName = table_name
            )

    except Exception as e:
        return f"Error: {e}"

    return {"Table Deleted" : table_name}

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Target Table Name", "id" : "table-name-text-input", "type" : "text", "placeholder" : "data-bucket", "element_type" : "dcc.Input"},
        {"title" : "Table Region Name (Optional)", "id" : "region-name-text-input", "type" : "text", "placeholder" : "us-east-1", "element_type" : "dcc.Input"},
        {"title" : "Enter [confirm delete]", "id" : "confirm-text-input", "type" : "text", "placeholder" : "[confirm delete]", "element_type" : "dcc.Input"}
    ]