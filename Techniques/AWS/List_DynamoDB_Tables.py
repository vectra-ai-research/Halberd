'''
Module Name: List_DynamoDB_Tables
Module Description: List tables associated with current account in dynamodb
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client/list_tables.html
'''
from core.AWSFunctions import CreateClient, valid_aws_regions

def TechniqueMain(region_name = None, limit = None):

    # set default region
    if region_name in [None, ""]:
        region_name = "us-east-1"

    if region_name not in valid_aws_regions:
        return False, {"Error" : "Invalid Region Name"}, None

    # initialize boto3 dynamodb client
    my_client = CreateClient('dynamodb', region_name = region_name)

    try:
        # list dynamodb tables
        if limit in [None, ""]:
            raw_response = my_client.list_tables()
        else:
            raw_response = my_client.list_tables(
                Limit = limit
            )
        try:
            # parse raw response => pretty response
            pretty_response = {}
            all_tables = raw_response['TableNames']
            
            # operation successful
            if 200 <= raw_response['ResponseMetadata']['HTTPStatusCode'] <300:
                for table in all_tables:
                    pretty_response[table] = {
                        "Table Name" : table,
                        "Region" : region_name
                    }
                return True, raw_response, pretty_response
            else:
                return False, {"Error" : raw_response}, None
        except:
            # return only raw response if pretty response fails
            return True, raw_response, None

    except Exception as e:
        return False, {"Error" : e}, None

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Region Name (Optional)", "id" : "region-name-text-input", "type" : "text", "placeholder" : "us-east-1", "element_type" : "dcc.Input"},
        {"title" : "Result Limit (Optional", "id" : "result-limit-text-input", "type" : "number", "placeholder" : "100", "element_type" : "dcc.Input"}
    ]