import string
from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry

from typing import Dict, Any, Tuple, List
import json
import base64

import concurrent.futures
import itertools
import os
import pycountry

from core.gcp.gcp_access import GCPAccess
from google.cloud import compute
from google.api_core.exceptions import PermissionDenied, Forbidden
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.oauth2.credentials import Credentials as UserAccountCredentials
from google.oauth2.credentials import Credentials as ShortLivedTokenCredentials
from google.auth.transport.requests import Request

@TechniqueRegistry.register
class GCPEnumerateComputeEngineInstances(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            ),
            MitreTechnique(
                technique_id="T1046",
                technique_name="Cloud Infrastructure Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            ),
            MitreTechnique(
                technique_id="T1082",
                technique_name="System Information Discovery",
                tactics=["Discovery"],
                sub_technique_name=None
            )
        ]
        technique_notes = [
            TechniqueNote("Enumerate any instance require compute.instances.list permission"),
            TechniqueNote("List all zone require compute.zones.list permission"),
            TechniqueNote("Obtain effective firewalls require compute.instances.getEffectiveFirewalls permission")
        ]

        technique_refs = [
            TechniqueReference("GCP SDK Documentation: gcloud compute instances list", "https://cloud.google.com/sdk/gcloud/reference/compute/instances/list"),
            TechniqueReference("GCP CE Regions and Zones", "https://cloud.google.com/compute/docs/regions-zones"),
            TechniqueReference("GCP CE Instance Types", "https://cloud.google.com/compute/docs/machine-resource"),
            TechniqueReference("GCP NGFW VPC Firewall Rules", "https://cloud.google.com/firewall/docs/firewalls"),
            TechniqueReference("GCP NGFW Firewall Policies", "https://cloud.google.com/firewall/docs/firewall-policies-overview"),
        ]

        super().__init__(
            name="Enumerate Compute Engines",
            description=("Performs comprehensive compute engine instance enumeration. "
            
            "The technique supports targeted enumeration in large environments through multiple filtering options: "
            "1. Project ID: Limit scope to specific projects "
            "2. Location: Target specific geographic zones"
            "3. Network Tags: Filter by network tags "
            "4. Firewall Detail: Boolean options to enumerate instance firewall"),
            mitre_techniques=mitre_techniques,
            references=technique_refs,
            notes=technique_notes
        )

    def _list_instances (self, location: str, project_id: str, compute_client: compute.InstancesClient, network_tags: list[str] = None, firewall_detail: bool = True) -> List[Dict[str, Any]]:
        instances_on_location = []
        instances_collected = compute_client.list(zone=location, project=project_id)
        for instance in instances_collected._response.items:
            if network_tags:
                if not any(tag in instance.tags.items for tag in network_tags):
                    continue
            instance_disks = []
            instance_network_interfaces = []
            instance_network_tags = []

            for disk in instance.disks:
                instance_disk_details = {
                    "boot_device": disk.boot,
                    "mode": disk.mode,
                    "type": disk.type,
                    "license": disk.licenses,
                    "auto_delete": disk.auto_delete,
                    "disk_size_gb": disk.disk_size_gb,
                    "device_name": disk.device_name,
                }

                instance_disks.append(instance_disk_details)
            
                for network_interface in instance.network_interfaces:
                    firewalls = []
                    firewall_policies = []
                    if firewall_detail:
                        try:
                            firewalls_associated = compute_client.get_effective_firewalls(
                                project=project_id,
                                zone=location,
                                instance=instance.name,
                                network_interface=network_interface.name
                            )

                            

                            for firewall in firewalls_associated.firewalls:
                                firewall_type = "ALLOWED" if len(firewall.allowed) >= 1 else "DENIED"
                                firewall_rules = []


                                if firewall_type == "ALLOWED":
                                    for allowed in firewall.allowed:
                                        firewall_rule = {
                                            "protocol": allowed.I_p_protocol,
                                            "ports": ", ".join(map(str, allowed.ports)) if allowed.ports else "all ports"
                                        }
                                        firewall_rules.append(firewall_rule)
                                else: 
                                    for denied in firewall.denied:
                                        firewall_rule = {
                                            "protocol": denied.I_p_protocol,
                                            "ports": ", ".join(map(str, denied.ports)) if denied.ports else "all ports"
                                        }
                                        firewall_rules.append(firewall_rule)
                                firewall_details = {
                                    # "rule_id": firewall.id,
                                    "name": firewall.name,
                                    "priority": firewall.priority,
                                    "direction": firewall.direction,
                                    "type": firewall_type,
                                    **({
                                        "allowed": firewall_rule
                                    } if firewall_type == "ALLOWED" else {
                                        "denied": firewall_rule
                                    }),
                                    **({
                                        "destination_ranges": ", ".join(map(str, firewall.destination_ranges)),
                                    } if firewall.direction == "EGRESS" else {
                                        **({"source_tags": ", ".join(map(str, firewall.source_tags))} if firewall.source_tags else {}),
                                        **({"source_ranges": ", ".join(map(str, firewall.source_ranges))} if firewall.source_ranges else {}),
                                        **({"source_service_accounts": ", ".join(map(str, firewall.source_service_accounts))} if firewall.source_service_accounts else {}),
                                    })
                                }

                                firewalls.append(firewall_details)

                            for firewall_policy in firewalls_associated.firewall_policys:
                                
                                firewall_policy_rules = []

                                for firewall_policy_rule in firewall_policy.rules:
                                    firewall_policy_rule_protos_ports = []
                                    firewall_policy_rule_source_secure_tags = []
                                    for proto_ports in firewall_policy_rule.match.layer4_configs:
                                        firewall_policy_rule_protos_ports.append({
                                            "protocol": proto_ports.ip_protocol,
                                            "ports": ", ".join(map(str, proto_ports.ports)) if proto_ports.ports else "all ports"
                                        })
                                    for secure_tags in firewall_policy_rule.match.src_secure_tags:
                                        firewall_policy_rule_source_secure_tags.append({
                                            "name": secure_tags.name,
                                            "state": secure_tags.state
                                        })
                                    firewall_policy_rule_dest_region = []
                                    firewall_policy_rule_src_region = []

                                    not_listed_region_code = [
                                        {
                                            "code" : "XC",
                                            "name" : "Crimea"
                                        },
                                        {
                                            "code" : "XD",
                                            "name" : " So-Called Donetsk People's Republic and Luhansk People’s Republic"
                                        }

                                    ]
                                    if firewall_policy_rule.match.dest_region_codes :
                                        for dest_region_code in firewall_policy_rule.match.dest_region_codes:
                                            region_name = None
                                            match = None
                                            for region in not_listed_region_code:
                                                if region["code"] == dest_region_code:
                                                    match = region
                                                    break
                                            if match:
                                                region_name = match["name"]
                                            else:
                                                country = pycountry.countries.get(alpha_2=dest_region_code)
                                                region_name = country.name if country else dest_region_code

                                            region = f"{dest_region_code} - {region_name}"
                                            firewall_policy_rule_dest_region.append(region)
                                
                                    if firewall_policy_rule.match.src_region_codes :
                                        for src_region_code in firewall_policy_rule.match.src_region_codes:
                                            region_name = None
                                            match = None
                                            for region in not_listed_region_code:
                                                if region["code"] == src_region_code:
                                                    match = region
                                                    break
                                            if match:
                                                region_name = match["name"]
                                            else:
                                                country = pycountry.countries.get(alpha_2=src_region_code)
                                                region_name = country.name if country else src_region_code
                                            
                                            region = f"{src_region_code} - {region_name}"
                                            firewall_policy_rule_src_region.append(region)

                                    

                                    firewall_policy_rule_details = {
                                        "action" : firewall_policy_rule.action,
                                        "direction" : firewall_policy_rule.direction,
                                        "disabled" : firewall_policy_rule.disabled,
                                        "priority" : firewall_policy_rule.priority,
                                        **({"destination" : {
                                            **({"address_groups": ", ".join(map(str, firewall_policy_rule.match.dest_address_groups))} if firewall_policy_rule.match.dest_address_groups else {}),
                                            **({"fqdns": ", ".join(map(str, firewall_policy_rule.match.dest_fqdns))} if firewall_policy_rule.match.dest_fqdns else {}),
                                            **({"ip_ranges": ", ".join(map(str, firewall_policy_rule.match.dest_ip_ranges))} if firewall_policy_rule.match.dest_ip_ranges else {}),
                                            **({"region_codes": ", ".join(map(str, firewall_policy_rule_dest_region))} if firewall_policy_rule_dest_region else {}),
                                            **({"threate_intelligence": ", ".join(map(str, firewall_policy_rule.match.dest_threat_intelligences))} if firewall_policy_rule.match.dest_threat_intelligences else {})
                                        }} if firewall_policy_rule.match.dest_address_groups or 
                                        firewall_policy_rule.match.dest_fqdns or 
                                        firewall_policy_rule.match.dest_ip_ranges or 
                                        firewall_policy_rule.match.dest_region_codes or
                                        firewall_policy_rule.match.dest_threat_intelligences else {}),
                                        **({"source" : {
                                            **({"address_groups": ", ".join(map(str, firewall_policy_rule.match.src_address_groups))} if firewall_policy_rule.match.src_address_groups else {}),
                                            **({"fqdns": ", ".join(map(str, firewall_policy_rule.match.src_fqdns))} if firewall_policy_rule.match.src_fqdns else {}),
                                            **({"ip_ranges": ", ".join(map(str, firewall_policy_rule.match.src_ip_ranges))} if firewall_policy_rule.match.src_ip_ranges else {}),
                                            **({"region_codes": ", ".join(map(str, firewall_policy_rule_src_region))} if firewall_policy_rule_src_region else {}),
                                            **({"threate_intelligence": ", ".join(map(str, firewall_policy_rule.match.src_threat_intelligences))} if firewall_policy_rule.match.src_threat_intelligences else {}),
                                            **({"secure_tags": firewall_policy_rule_source_secure_tags } if firewall_policy_rule_source_secure_tags else {})
                                        }} if firewall_policy_rule.match.src_address_groups or 
                                        firewall_policy_rule.match.src_fqdns or 
                                        firewall_policy_rule.match.src_ip_ranges or 
                                        firewall_policy_rule.match.src_region_codes or
                                        firewall_policy_rule.match.src_threat_intelligences or
                                        firewall_policy_rule_source_secure_tags else {}),
                                        **({"ports" : firewall_policy_rule_protos_ports} if firewall_policy_rule_protos_ports else {})
                                    }

                                    firewall_policy_rules.append(firewall_policy_rule_details)

                                firewall_policy_detail = {
                                    "name" : firewall_policy.name,
                                    "priority" : firewall_policy.priority,
                                    "type" : firewall_policy.type_,
                                    "rules": firewall_policy_rules
                                }

                                firewall_policies.append(firewall_policy_detail)

                            firewalls = sorted(firewalls, key=lambda x: (x["priority"], x["type"] != "DENIED"))

                            firewall_policies_priority_by_type = {"HIERARCHY": 0, "NETWORK": 1, "NETWORK_REGIONAL": 2}

                            firewall_policies = sorted(firewall_policies, key=lambda x: (x["priority"], firewall_policies_priority_by_type[x["type"]]))
                        except Exception:
                            raise
                    network_interface_details = {
                        "name": network_interface.name,
                        "network": network_interface.network,
                        "subnetwork": network_interface.subnetwork,
                        "stack_type": network_interface.stack_type,
                        "internal_ipv4": network_interface.network_i_p,
                        "public_ipv4": network_interface.access_configs[0].nat_i_p,
                        "internal_ipv6": network_interface.ipv6_address,
                        "public_ipv6": network_interface.access_configs[0].external_ipv6,
                        # "kind": network_interface.kind  
                        **({
                            "firewalls_rules": firewalls,
                            "firewalls_policies": firewall_policies}
                            if firewall_detail else {})
                        
                    }

            instance_network_interfaces.append(network_interface_details)
            
            for tag in instance.tags.items:
                instance_network_tags.append(tag)
            
            instance_details = {
                "name": instance.name,
                "machine_type": instance.machine_type,
                "zone": instance.zone,
                "status": instance.status,
                "labels": instance.labels,
                "tags": instance_network_tags,
                # "metadata": instance.metadata,
                "service_account" : {
                    "email" : instance.service_accounts[0].email,
                    "scopes" : instance.service_accounts[0].scopes
                },
                "disks": instance_disks,
                "network_interfaces": instance_network_interfaces,
            }

            instances_on_location.append(instance_details)
        return instances_on_location


    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            project_id: str = kwargs.get("project_id", None)
            locations: list[str] = kwargs.get("locations").split(",") if kwargs.get("locations") else []
            network_tags: list[str] =  kwargs.get("network_tags").split(",") if kwargs.get("network_tags") else []
            firewall_detail: bool = kwargs.get("firewall_detail", False)
            
            # Get GCP credentials from GCP access manager
            manager = GCPAccess()
            manager.get_current_access()
            credential = manager.credential

            # Initialize compute client with project if specified
            if project_id is None:
                project_id = credential.project_id
            compute_client = compute.InstancesClient(credentials=credential)
            
            if len(locations) == 0:  # Check if locations is empty
                try: 
                    zone_client = compute.ZonesClient(credentials=credential)
                    zones = zone_client.list(project=project_id)
                    for zone in zones._response.items:
                        locations.append(zone.name)
                except Exception:
                    raise
            instances = []
            try:
                # Run in parallel using ThreadPoolExecutor
                worker = 0

                if (os.cpu_count() * 5) > len(locations):
                    worker = len(locations)
                else:
                    worker = os.cpu_count() * 5
                with concurrent.futures.ThreadPoolExecutor(max_workers=worker) as executor:
                    results = executor.map(self._list_instances, locations, itertools.repeat(project_id), itertools.repeat(compute_client), itertools.repeat(network_tags), itertools.repeat(firewall_detail))

                # Collect results safely
                for result in results:
                    instances.extend(result)
                
                return ExecutionStatus.SUCCESS, {
                    "message": "Successfully enumerated compute engine instances",
                    "value": {
                        "total_instances": len(instances),
                        "instances": instances
                    }
                }
                        
            except Exception:
                raise
        except (PermissionDenied,Forbidden) as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate compute engine instances - Permission denied or Forbidden"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to enumerate compute engine instances"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "project_id": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Project ID",
                "input_field_type": "text"
            },
            "locations": {
                "type": "str",
                "required": False,
                "default": None,
                "name": 'Locations (e.g., us-central1-a, asia-southeast2-c, with "," separator)',
                "input_field_type": "text"
            },
            "network_tags": {
                "type": "str",
                "required": False,
                "default": None,
                "name": 'Network Tags (with "," separator")',
                "input_field_type": "text"
            },
            "firewall_detail": {
                "type": "bool",
                "required": False,
                "default": True,
                "name": 'Firewall Detail',
                "input_field_type": "bool"
            }
        }