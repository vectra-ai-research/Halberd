'''
Module Name: EC2_Enum
Description: Enumerate instances in AWS EC2. Pass additional parameters to filter results.
Ref: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_instances.html
'''
from core.AWSFunctions import valid_aws_regions, CreateClient

def TechniqueMain(region_name = "us-east-1", instance_id = None, state = None, max_results = None, dryRun = False):

    # set default region
    if region_name in [None, ""]:
        region_name = "us-east-1"
    
    # validate user input for region
    if region_name not in valid_aws_regions:
        return "Invalid Region Name"

    # initialize boto3 ec2 client
    my_client = CreateClient('ec2', region_name = region_name)

    # create filter based on user supplied parameters
    filters = []

    if state:
        filters.append(
            {
                'Name': 'instance-state-name',
                'Values': [state]
            },
        )

    if instance_id:
        filters.append(
            {
                'Name': 'instance-id',
                'Values': [instance_id]
            },
        )

    if dryRun:
        dryRun = True
    else:
        dryRun = False

    # Fetch EC2 instances
    try:
        if max_results:
            response = my_client.describe_instances(Filters = filters, DryRun = dryRun, MaxResults = max_results)
        else:
            response = my_client.describe_instances(Filters = filters, DryRun = dryRun)

    except Exception as e:
        return e       
    
    # Enumerate EC2 instance details
    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_details = {
                'InstanceId': instance['InstanceId'],
                'InstanceType': instance['InstanceType'],
                'State': instance['State']['Name'],
                'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A'),
                'Monitoring': instance.get('Monitoring', 'N/A').get('State','N/A'),
                'LaunchTime': instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S'),
                'Tags': instance.get('Tags', [])
            }
            instances.append(instance_details)

    return instances

def TechniqueInputSrc() -> list:
    '''This function returns the input fields required as parameters for the technique execution'''
    return [
        {"title" : "Region Name (Optional)", "id" : "ec2-region-name-text-input", "type" : "text", "placeholder" : "us-east-1", "element_type" : "dcc.Input"},
        {"title" : "Instance ID (Optional)", "id" : "ec2-instance-id-text-input", "type" : "text", "placeholder" : "i-myinstance12432423", "element_type" : "dcc.Input"},
        {"title" : "State (Optional)", "id" : "ec2-instance-state-text-input", "type" : "text", "placeholder" : "us-west-2", "element_type" : "dcc.Input"},
        {"title" : "Max Results (Optional)", "id" : "ec2-enum-max-result-input", "type" : "number", "placeholder" : "5", "element_type" : "dcc.Input"},
        {"title" : "Test Permission Before Enumeration?", "id" : "ec2-dryrun-boolean-switch", "type" : "text", "placeholder" : "False", "element_type" : "daq.BooleanSwitch"}
    ]