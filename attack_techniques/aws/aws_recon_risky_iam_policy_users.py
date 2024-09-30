from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3
import json

@TechniqueRegistry.register
class AWSReconRiskyIAMPolicyUsers(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1069",
                technique_name="Permission Groups Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Recon Risky IAM Policy User", "This module checks for potential IAM privilege escalation paths in an AWS environment. Its possible to gain higher privileges by exploiting misconfigurations or overly permissive IAM policies. This technique analyzes users IAM policies to identify risky permissions that could lead to privilege escalation.", mitre_techniques)
        
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        def has_risky_permissions(policy_document):
            """Checks if a IAM policy has risky permissions"""
            risky_actions = [
                "iam:AttachRolePolicy",
                "iam:CreatePolicyVersion",
                "iam:SetDefaultPolicyVersion",
                "iam:PassRole",
                "lambda:CreateFunction",
                "lambda:InvokeFunction"
            ]
            
            for statement in policy_document['Statement']:
                if statement['Effect'] == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    for action in actions:
                        if action in risky_actions or action == '*':
                            return True
            return False
        
        try:
            # Initialize boto3 client
            my_client = boto3.client("iam")

            # Get all IAM users
            users = my_client.list_users()['Users']

            result = []
            for user in users:
                username = user['UserName']
                # Get list of policnames for user
                user_policies = my_client.list_user_policies(UserName=username)['PolicyNames']
                
                for policy_name in user_policies:
                    # Get policy details
                    policy = my_client.get_user_policy(UserName=username, PolicyName=policy_name)
                    
                    # Check for risky permissions in policy
                    if has_risky_permissions(policy['PolicyDocument']):
                        result.append({
                            "username": username,
                            "policy_name" : policy_name,
                            "policy_document" : json.dumps(policy['PolicyDocument'], indent=2)
                        })

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully reconned {len(result)} risky policies" if result else "No risky policies found",
                "value": result
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to recon risky policies"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}