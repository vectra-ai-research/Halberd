from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueReference, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraReconRoleInfo(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1069.003",
                technique_name="Permission Groups Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Groups"
            )
        ]
        
        technique_notes = [
            TechniqueNote("This technique works with both active directory roles and role templates - specify either a role name (e.g., 'Global Administrator') or a role ID/template ID"),
            TechniqueNote("Some information may require higher privileges - the technique will indicate where data could not be retrieved due to insufficient permissions")
        ]
        
        technique_refs = [
            TechniqueReference("Azure AD Built-in Roles", "https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference"),
            TechniqueReference("Microsoft Graph API - Directory Roles", "https://docs.microsoft.com/en-us/graph/api/resources/directoryrole")
        ]
        
        super().__init__(
            "Recon Role Info", 
            "Perform comprehensive reconnaissance on Entra ID directory role to gather intelligence for privilege escalation and attack path planning. This technique takes a role name or role ID as input and collects all available information including role definitions, current members, eligible assignments, administrative unit scopes, and permission boundaries. The reconnaissance covers both active role assignments and PIM (Privileged Identity Management) eligible assignments, providing a complete picture of the role's usage and potential attack vectors.", 
            mitre_techniques,
            references=technique_refs,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            role_input: str = kwargs.get('role_input', '').strip()
            include_pim_data: bool = kwargs.get('include_pim_data', True)
            
            if role_input in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "Role name or role ID is required"
                }
            
            if include_pim_data in [None, ""]:
                include_pim_data = True
            
            # Initialize results structure
            recon_results = {
                "role_basic_info": {},
                "role_members": [],
                "role_assignments": [],
                "administrative_units": [],
                "pim_eligible_assignments": [],
                "role_permissions": [],
                "privilege_analysis": {},
                "access_restrictions": []
            }
            
            # Step 1: Identify the target role
            role_info = self._identify_target_role(role_input)
            if not role_info:
                return ExecutionStatus.FAILURE, {
                    "error": "Role Not Found",
                    "message": f"Could not find role matching input: {role_input}"
                }
            
            recon_results["role_basic_info"] = role_info
            
            # Step 2: Get role members
            members_result = self._get_role_members(role_info.get('id'))
            recon_results["role_members"] = members_result["members"]
            
            # Step 3: Get detailed role assignments
            assignments_result = self._get_role_assignments(role_info.get('roleTemplateId', role_info.get('id')))
            recon_results["role_assignments"] = assignments_result["assignments"]
            
            # Step 4: Check administrative unit assignments
            admin_units_result = self._get_administrative_unit_assignments(role_info.get('roleTemplateId'))
            recon_results["administrative_units"] = admin_units_result["admin_units"]
            
            # Step 5: Get PIM eligible assignments (if requested)
            if include_pim_data:
                pim_result = self._get_pim_eligible_assignments(role_info.get('roleTemplateId'))
                recon_results["pim_eligible_assignments"] = pim_result["eligible_assignments"]
            
            # Step 6: Analyze role permissions and scope
            permissions_result = self._analyze_role_permissions(role_info.get('roleTemplateId'))
            recon_results["role_permissions"] = permissions_result["permissions"]
            
            # Step 7: Generate privilege analysis summary
            privilege_analysis = self._generate_privilege_analysis(recon_results)
            recon_results["privilege_analysis"] = privilege_analysis
            
            # Determine execution status based on data collected
            total_sections = 6 if include_pim_data else 5
            successful_sections = sum([
                1 if recon_results["role_basic_info"] else 0,
                1 if recon_results["role_members"] else 0,
                1 if recon_results["role_assignments"] else 0,
                1 if recon_results["administrative_units"] else 0,
                1 if recon_results["pim_eligible_assignments"] or not include_pim_data else 0,
                1 if recon_results["role_permissions"] else 0
            ])

            if successful_sections == total_sections:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully performed deep reconnaissance on role '{role_info.get('displayName', role_input)}'",
                    "value": recon_results
                }
            elif successful_sections > total_sections / 2:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Partial reconnaissance completed on role '{role_info.get('displayName', role_input)}' - some data unavailable due to permissions",
                    "value": recon_results
                }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": f"Limited reconnaissance data collected for role '{role_info.get('displayName', role_input)}'",
                    "message": "Failed to perform role reconnaissance"
                }
            
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to perform role reconnaissance"
            }

    def _identify_target_role(self, role_input: str) -> Dict[str, Any]:
        """Identify target role by name, ID, or template ID"""
        try:
            # First try to get role by ID
            endpoint_url = f"https://graph.microsoft.com/v1.0/directoryRoles/{role_input}"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' not in response:
                return {
                    "id": response.get("id", "N/A"),
                    "displayName": response.get("displayName", "N/A"),
                    "description": response.get("description", "N/A"),
                    "roleTemplateId": response.get("roleTemplateId", "N/A")
                }
        except:
            pass
        
        # If not found by ID, search all directory roles
        try:
            endpoint_url = "https://graph.microsoft.com/v1.0/directoryRoles"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' not in response and response:
                for role in response:
                    # Match by display name (case insensitive)
                    if role.get("displayName", "").lower() == role_input.lower():
                        return {
                            "id": role.get("id", "N/A"),
                            "displayName": role.get("displayName", "N/A"),
                            "description": role.get("description", "N/A"),
                            "roleTemplateId": role.get("roleTemplateId", "N/A")
                        }
                    # Match by role template ID
                    if role.get("roleTemplateId") == role_input:
                        return {
                            "id": role.get("id", "N/A"),
                            "displayName": role.get("displayName", "N/A"),
                            "description": role.get("description", "N/A"),
                            "roleTemplateId": role.get("roleTemplateId", "N/A")
                        }
        except:
            pass
        
        # If still not found, check role templates
        try:
            endpoint_url = "https://graph.microsoft.com/v1.0/directoryRoleTemplates"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' not in response and response:
                for template in response:
                    if (template.get("displayName", "").lower() == role_input.lower() or 
                        template.get("id") == role_input):
                        return {
                            "id": template.get("id", "N/A"),
                            "displayName": template.get("displayName", "N/A"),
                            "description": template.get("description", "N/A"),
                            "roleTemplateId": template.get("id", "N/A"),
                            "is_template": True
                        }
        except:
            pass
        
        return None

    def _get_role_members(self, role_id: str) -> Dict[str, Any]:
        """Get all members of the specified role"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' in response:
                return {
                    "members": [],
                    "error": f"Failed to get role members: {response.get('error', {}).get('message', 'Unknown error')}"
                }
            
            members = []
            if response:
                for member in response:
                    members.append({
                        "id": member.get("id", "N/A"),
                        "displayName": member.get("displayName", "N/A"),
                        "userPrincipalName": member.get("userPrincipalName", "N/A"),
                        "objectType": member.get("@odata.type", "N/A").replace("#microsoft.graph.", ""),
                        "accountEnabled": member.get("accountEnabled", "N/A"),
                        "userType": member.get("userType", "N/A"),
                        "mail": member.get("mail", "N/A")
                    })
            
            return {
                "members": members,
                "member_count": len(members)
            }
            
        except Exception as e:
            return {
                "members": [],
                "error": f"Exception getting role members: {str(e)}"
            }

    def _get_role_assignments(self, role_template_id: str) -> Dict[str, Any]:
        """Get detailed role assignments including scope and conditions"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{role_template_id}'"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' in response:
                return {
                    "assignments": [],
                    "error": f"Failed to get role assignments: {response.get('error', {}).get('message', 'Unknown error')}"
                }
            
            assignments = []
            if response:
                for assignment in response:
                    # Get principal details
                    principal_id = assignment.get("principalId")
                    principal_details = self._get_principal_details(principal_id)
                    
                    assignments.append({
                        "id": assignment.get("id", "N/A"),
                        "principalId": principal_id,
                        "principalDetails": principal_details,
                        "directoryScopeId": assignment.get("directoryScopeId", "N/A"),
                        "appScopeId": assignment.get("appScopeId", "N/A"),
                        "assignmentType": assignment.get("assignmentType", "Direct"),
                        "memberType": assignment.get("memberType", "Direct")
                    })
            
            return {
                "assignments": assignments,
                "assignment_count": len(assignments)
            }
            
        except Exception as e:
            return {
                "assignments": [],
                "error": f"Exception getting role assignments: {str(e)}"
            }

    def _get_administrative_unit_assignments(self, role_template_id: str) -> Dict[str, Any]:
        """Get administrative unit scoped role assignments"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{role_template_id}' and directoryScopeId ne '/'"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' in response:
                return {
                    "admin_units": [],
                    "error": f"Failed to get admin unit assignments: {response.get('error', {}).get('message', 'Unknown error')}"
                }
            
            admin_unit_assignments = []
            if response:
                for assignment in response:
                    scope_id = assignment.get("directoryScopeId", "")
                    if scope_id and scope_id != "/":
                        # Extract AU ID and get details
                        au_id = scope_id.replace("/administrativeUnits/", "")
                        au_details = self._get_administrative_unit_details(au_id)
                        
                        admin_unit_assignments.append({
                            "assignmentId": assignment.get("id", "N/A"),
                            "administrativeUnitId": au_id,
                            "administrativeUnitDetails": au_details,
                            "principalId": assignment.get("principalId", "N/A")
                        })
            
            return {
                "admin_units": admin_unit_assignments,
                "admin_unit_count": len(admin_unit_assignments)
            }
            
        except Exception as e:
            return {
                "admin_units": [],
                "error": f"Exception getting admin unit assignments: {str(e)}"
            }

    def _get_pim_eligible_assignments(self, role_template_id: str) -> Dict[str, Any]:
        """Get PIM eligible assignments for the role"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$filter=roleDefinitionId eq '{role_template_id}'"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' in response:
                return {
                    "eligible_assignments": [],
                    "error": f"Failed to get PIM eligible assignments: {response.get('error', {}).get('message', 'Unknown error')}"
                }
            
            eligible_assignments = []
            if response:
                for assignment in response:
                    principal_details = self._get_principal_details(assignment.get("principalId"))
                    
                    eligible_assignments.append({
                        "id": assignment.get("id", "N/A"),
                        "principalId": assignment.get("principalId", "N/A"),
                        "principalDetails": principal_details,
                        "directoryScopeId": assignment.get("directoryScopeId", "N/A"),
                        "status": assignment.get("status", "N/A"),
                        "scheduleInfo": assignment.get("scheduleInfo", {}),
                        "memberType": assignment.get("memberType", "N/A")
                    })
            
            return {
                "eligible_assignments": eligible_assignments,
                "eligible_count": len(eligible_assignments)
            }
            
        except Exception as e:
            return {
                "eligible_assignments": [],
                "error": f"Exception getting PIM eligible assignments: {str(e)}"
            }

    def _analyze_role_permissions(self, role_template_id: str) -> Dict[str, Any]:
        """Analyze role permissions and capabilities"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/{role_template_id}"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' in response:
                return {
                    "permissions": [],
                    "error": f"Failed to get role permissions: {response.get('error', {}).get('message', 'Unknown error')}"
                }
            
            permissions_info = {
                "rolePermissions": response.get("rolePermissions", []),
                "isBuiltIn": response.get("isBuiltIn", False),
                "isEnabled": response.get("isEnabled", True),
                "version": response.get("version", "N/A"),
                "templateId": response.get("templateId", "N/A")
            }
            
            return {
                "permissions": [permissions_info]
            }
            
        except Exception as e:
            return {
                "permissions": [],
                "error": f"Exception analyzing role permissions: {str(e)}"
            }

    def _get_principal_details(self, principal_id: str) -> Dict[str, Any]:
        """Get details about a principal (user, group, or service principal)"""
        try:
            # Try user first
            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{principal_id}"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' not in response:
                return {
                    "type": "user",
                    "displayName": response.get("displayName", "N/A"),
                    "userPrincipalName": response.get("userPrincipalName", "N/A"),
                    "accountEnabled": response.get("accountEnabled", "N/A"),
                    "userType": response.get("userType", "N/A")
                }
            
            # Try group
            endpoint_url = f"https://graph.microsoft.com/v1.0/groups/{principal_id}"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' not in response:
                return {
                    "type": "group",
                    "displayName": response.get("displayName", "N/A"),
                    "groupTypes": response.get("groupTypes", []),
                    "securityEnabled": response.get("securityEnabled", "N/A")
                }
            
            # Try service principal
            endpoint_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{principal_id}"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' not in response:
                return {
                    "type": "servicePrincipal",
                    "displayName": response.get("displayName", "N/A"),
                    "appId": response.get("appId", "N/A"),
                    "servicePrincipalType": response.get("servicePrincipalType", "N/A")
                }
            
            return {
                "type": "unknown",
                "id": principal_id,
                "error": "Could not determine principal type"
            }
            
        except Exception as e:
            return {
                "type": "error",
                "id": principal_id,
                "error": str(e)
            }

    def _get_administrative_unit_details(self, au_id: str) -> Dict[str, Any]:
        """Get administrative unit details"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/administrativeUnits/{au_id}"
            response = GraphRequest().get(url=endpoint_url)
            
            if 'error' not in response:
                return {
                    "displayName": response.get("displayName", "N/A"),
                    "description": response.get("description", "N/A"),
                    "visibility": response.get("visibility", "N/A")
                }
            else:
                return {
                    "error": f"Could not retrieve AU details: {response.get('error', {}).get('message', 'Unknown error')}"
                }
                
        except Exception as e:
            return {
                "error": f"Exception getting AU details: {str(e)}"
            }

    def _generate_privilege_analysis(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate role's privilege analysis"""
        analysis = {
            "memberCount": len(recon_data.get("role_members", [])),
            "assignmentCount": len(recon_data.get("role_assignments", [])),
            "eligibleCount": len(recon_data.get("pim_eligible_assignments", [])),
            "adminUnitCount": len(recon_data.get("administrative_units", [])),
            "attackSurface": "Unknown"
        }
        
        # Determine attack surface
        total_access = analysis["memberCount"] + analysis["eligibleCount"]
        
        if total_access == 0:
            analysis["attackSurface"] = "No Active Assignments"
        elif total_access <= 5:
            analysis["attackSurface"] = "Limited"
        elif total_access <= 20:
            analysis["attackSurface"] = "Moderate"
        else:
            analysis["attackSurface"] = "High"
        
        return analysis

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "role_input": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "Role Name or ID", 
                "input_field_type": "text"
            },
            "include_pim_data": {
                "type": "bool", 
                "required": False, 
                "default": True, 
                "name": "Include PIM Eligible Assignments", 
                "input_field_type": "bool"
            }
        }