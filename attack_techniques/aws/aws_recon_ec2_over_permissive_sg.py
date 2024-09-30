from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import boto3

@TechniqueRegistry.register
class AWSReconEC2OverPermissiveSG(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1046",
                technique_name="Network Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        super().__init__("Recon EC2 Over Permissive Security Groups", "This module identifies overly permissive security group rules in an AWS environment. Its possible to exploit overly permissive security group rules to gain unauthorized access to EC2 instances or other AWS resources. This module analyzes security group rules to identify potentially risky configurations.", mitre_techniques)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        def is_rule_permissive(rule):
            if 'IpRanges' in rule:
                for ip_range in rule['IpRanges']:
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        return True
            
            if 'Ipv6Ranges' in rule:
                for ip_range in rule['Ipv6Ranges']:
                    if ip_range['CidrIpv6'] == '::/0':
                        return True
            return False
        
        try:
            # Initialize boto3 client
            my_client = boto3.client('ec2')

            # Get all security groups
            security_groups = my_client.describe_security_groups()['SecurityGroups']

            permissive_rule = []
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                # Check inbound rules
                for rule in sg['IpPermissions']:
                    if is_rule_permissive(rule):
                        permissive_rule.append({
                            "security_group" : sg_name,
                            "sg_id" : sg_id,
                            "protocol" : rule.get('IpProtocol', 'All'),
                            "from_port" : rule.get('FromPort', 'All'),
                            "to_port" : rule.get('ToPort', 'All'),
                            "direction" : "inbound",
                            "message" : "Overly permissive inbound rule found in Security Group"
                        })

                # Check outbound rules
                for rule in sg['IpPermissionsEgress']:
                    if is_rule_permissive(rule):
                        permissive_rule.append({
                            "security_group" : sg_name,
                            "sg_id" : sg_id,
                            "protocol" : rule.get('IpProtocol', 'All'),
                            "from_port" : rule.get('FromPort', 'All'),
                            "to_port" : rule.get('ToPort', 'All'),
                            "direction" : "outbound",
                            "message" : "Overly permissive outbound rule found in Security Group"
                        })
                        
            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully reconned {len(permissive_rule)} overly permissive ec2 security groups" if permissive_rule else "No overly permissive ec2 security groups found",
                "value": permissive_rule
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to recon ec2 security groups"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {}