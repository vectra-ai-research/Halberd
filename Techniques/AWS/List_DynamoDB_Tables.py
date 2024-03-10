'''
Module Name: List_DynamoDB_Tables.py
Description: List tables associated with current account in dynamodb
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client/list_tables.html
'''
from core.AWSFunctions import CreateClient, valid_aws_regions

def TechniqueMain(region_name = None, limit = None):

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
        # list dynamodb tables
        if limit in [None, ""]:
            response = my_client.list_tables()
        else:
            response = my_client.list_tables(
                Limit = limit
            )
        
        tables = response['TableNames']
        return tables

    except Exception as e:
        return f"Failed to enumerate dynamodb tables: {e}"

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Region Name (Optional)", "id" : "region-name-text-input", "type" : "text", "placeholder" : "us-east-1", "element_type" : "dcc.Input"},
        {"title" : "Result Limit (Optional", "id" : "result-limit-text-input", "type" : "number", "placeholder" : "100", "element_type" : "dcc.Input"}
    ]