from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
import json

@TechniqueRegistry.register
class AWSReconS3PublicBuckets(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1619",
                technique_name="Cloud Storage Object Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Recon S3 Public Buckets", "This module identifies public S3 buckets in an AWS environment. This technique scans all S3 buckets in the account and checks their access control lists (ACLs) and policies to determine if they are publicly accessible.", mitre_techniques)
        
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        def is_acl_public(acl):
            for grant in acl['Grants']:
                # Ref: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
                if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    return True
            return False

        def is_policy_public(policy):
            policy_dict = policy['Policy']
            if isinstance(policy_dict, str):
                policy_dict = json.loads(policy_dict)
            
            for statement in policy_dict['Statement']:
                if statement['Effect'] == 'Allow' and statement['Principal'] == '*':
                    return True
            return False
        
        try:
            # Initialize boto3 client
            my_client = boto3.client('s3')

            # List all buckets
            buckets = my_client.list_buckets()['Buckets']

            public_buckets = []
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Check bucket ACL
                    acl = my_client.get_bucket_acl(Bucket=bucket_name)
                    if is_acl_public(acl):
                        public_buckets.append({
                            "bucket_name" : bucket_name,
                            "message" : "Public ACL found for bucket",
                            "acl_grants" : acl['Grants']})
                    
                    # Check bucket policy
                    try:
                        policy = my_client.get_bucket_policy(Bucket=bucket_name)
                        if is_policy_public(policy):
                            public_buckets.append({
                                "bucket_name" : bucket_name,
                                "message" : "Public policy found for bucket",
                                "policy" : policy['Policy']})
                    except my_client.exceptions.NoSuchBucketPolicy:
                        pass  # No bucket policy
                
                except my_client.exceptions.NoSuchBucket:
                    pass # Bucket not found
                except Exception as e:
                    pass # Error checking bucket
                        
            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully reconned {len(public_buckets)} public S3 buckets" if public_buckets else "No public S3 buckets found",
                "value": public_buckets
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to recon public S3 buckets"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}