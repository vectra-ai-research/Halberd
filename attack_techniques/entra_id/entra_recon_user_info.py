from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueReference, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.entra.graph_request import GraphRequest

@TechniqueRegistry.register
class EntraReconUserInfo(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1087.004",
                technique_name="Account Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Account"
            ),
            MitreTechnique(
                technique_id="T1069.003",
                technique_name="Permission Groups Discovery",
                tactics=["Discovery"],
                sub_technique_name="Cloud Groups"
            )
        ]
        
        references = [
            TechniqueReference(
                ref_title="Microsoft Graph User Resource Type",
                ref_link="https://docs.microsoft.com/en-us/graph/api/resources/user"
            ),
            TechniqueReference(
                ref_title="Microsoft Graph User API Reference",
                ref_link="https://docs.microsoft.com/en-us/graph/api/user-get"
            )
        ]
        
        notes = [
            TechniqueNote(
                "This technique requires User.Read.All or Directory.Read.All permissions. Some information may be restricted based on current permissions."
            ),
            TechniqueNote(
                "The technique attempts to gather role assignments, group memberships, and app assignments. Access to this information depends on the privileges of the current authentication context."
            )
        ]
        
        super().__init__(
            "Recon User Info", 
            "Perform comprehensive reconnaissance on a target Entra ID user account to gather detailed information. This technique enumerates all available user attributes, group memberships, role assignments, and application access rights to build a complete profile of the target user's identity and permissions within the tenant. The technique provides visibility into user contact information, organizational hierarchy through manager relationships, and security settings that may indicate account protection levels. It reveals group memberships that could be exploited for access to resources or privilege inheritance, directory role assignments that grant administrative capabilities, and application assignments that show what cloud resources the user can access. This comprehensive user profiling enables to assess the value of compromising the account and identify the most effective attack vectors for further exploitation.",
            mitre_techniques,
            references=references,
            notes=notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            user_identifier: str = kwargs.get('user_identifier', None)
            
            if user_identifier in [None, ""]:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid Technique Input",
                    "message": "User identifier (UPN or Object ID) is required"
                }

            results = {}
            failed_operations = []
            
            # 1. Get basic user information
            basic_info_success, basic_info = self._get_basic_user_info(user_identifier)
            if basic_info_success:
                results["basic_info"] = basic_info
            else:
                failed_operations.append("basic_user_info")
                results["basic_info"] = {"error": basic_info.get("error", "Failed to retrieve basic user information")}

            # 2. Get user's group memberships
            groups_success, groups_info = self._get_user_groups(user_identifier)
            if groups_success:
                results["group_memberships"] = groups_info
            else:
                failed_operations.append("group_memberships")
                results["group_memberships"] = {"error": groups_info.get("error", "Failed to retrieve group memberships")}

            # 3. Get user's directory role assignments
            roles_success, roles_info = self._get_user_directory_roles(user_identifier)
            if roles_success:
                results["directory_roles"] = roles_info
            else:
                failed_operations.append("directory_roles")
                results["directory_roles"] = {"error": roles_info.get("error", "Failed to retrieve directory roles")}

            # 4. Get user's application assignments
            apps_success, apps_info = self._get_user_app_assignments(user_identifier)
            if apps_success:
                results["app_assignments"] = apps_info
            else:
                failed_operations.append("app_assignments")
                results["app_assignments"] = {"error": apps_info.get("error", "Failed to retrieve application assignments")}

            # 5. Get user's manager information
            manager_success, manager_info = self._get_user_manager(user_identifier)
            if manager_success:
                results["manager_info"] = manager_info
            else:
                failed_operations.append("manager_info")
                results["manager_info"] = {"error": manager_info.get("error", "Failed to retrieve manager information")}

            # 6. Get user's direct reports
            reports_success, reports_info = self._get_user_direct_reports(user_identifier)
            if reports_success:
                results["direct_reports"] = reports_info
            else:
                failed_operations.append("direct_reports")
                results["direct_reports"] = {"error": reports_info.get("error", "Failed to retrieve direct reports")}

            # 7. Get user's owned objects
            owned_success, owned_info = self._get_user_owned_objects(user_identifier)
            if owned_success:
                results["owned_objects"] = owned_info
            else:
                failed_operations.append("owned_objects")
                results["owned_objects"] = {"error": owned_info.get("error", "Failed to retrieve owned objects")}

            # 8. Get user's registered devices
            devices_success, devices_info = self._get_user_registered_devices(user_identifier)
            if devices_success:
                results["registered_devices"] = devices_info
            else:
                failed_operations.append("registered_devices")
                results["registered_devices"] = {"error": devices_info.get("error", "Failed to retrieve registered devices")}

            results["summary"] = {
                "total_operations": 8,
                "successful_operations": 8 - len(failed_operations),
                "failed_operations": failed_operations,
                "user_identifier": user_identifier
            }

            # Determine execution status
            if not failed_operations:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully gathered complete user reconnaissance data",
                    "value": results
                }
            elif len(failed_operations) < 8:
                return ExecutionStatus.SUCCESS, {
                    "message": f"Gathered partial user reconnaissance data. Failed operations: {', '.join(failed_operations)}",
                    "value": results
                }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": results,
                    "message": f"Failed to gather user reconnaissance data"
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to perform user reconnaissance"
            }

    def _get_basic_user_info(self, user_identifier: str) -> Tuple[bool, Dict[str, Any]]:
        """Get primary user information"""
        try:
            # Use $select to get all relevant user properties
            select_params = [
                "id", "userPrincipalName", "displayName", "givenName", "surname", 
                "mail", "mailNickname", "jobTitle", "department", "companyName",
                "officeLocation", "city", "state", "country", "streetAddress",
                "postalCode", "businessPhones", "mobilePhone", "faxNumber",
                "employeeId", "employeeType", "preferredLanguage", "usageLocation",
                "userType", "accountEnabled", "createdDateTime", "lastPasswordChangeDateTime",
                "passwordPolicies", "assignedLicenses", "assignedPlans", "aboutMe"
            ]
            
            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_identifier}?$select={','.join(select_params)}"
            
            raw_response = GraphRequest().get(url=endpoint_url)

            if 'error' in raw_response:
                return False, {"error": f"Error {raw_response.get('error').get('code')}: {raw_response.get('error').get('message')}"}

            # Format the response
            user_info = {
                'object_id': raw_response.get('id', 'N/A'),
                'upn': raw_response.get('userPrincipalName', 'N/A'),
                'display_name': raw_response.get('displayName', 'N/A'),
                'given_name': raw_response.get('givenName', 'N/A'),
                'surname': raw_response.get('surname', 'N/A'),
                'mail': raw_response.get('mail', 'N/A'),
                'mail_nickname': raw_response.get('mailNickname', 'N/A'),
                'job_title': raw_response.get('jobTitle', 'N/A'),
                'department': raw_response.get('department', 'N/A'),
                'company_name': raw_response.get('companyName', 'N/A'),
                'office_location': raw_response.get('officeLocation', 'N/A'),
                'city': raw_response.get('city', 'N/A'),
                'state': raw_response.get('state', 'N/A'),
                'country': raw_response.get('country', 'N/A'),
                'street_address': raw_response.get('streetAddress', 'N/A'),
                'postal_code': raw_response.get('postalCode', 'N/A'),
                'business_phones': raw_response.get('businessPhones', []),
                'mobile_phone': raw_response.get('mobilePhone', 'N/A'),
                'fax_number': raw_response.get('faxNumber', 'N/A'),
                'employee_id': raw_response.get('employeeId', 'N/A'),
                'employee_type': raw_response.get('employeeType', 'N/A'),
                'preferred_language': raw_response.get('preferredLanguage', 'N/A'),
                'usage_location': raw_response.get('usageLocation', 'N/A'),
                'user_type': raw_response.get('userType', 'N/A'),
                'account_enabled': raw_response.get('accountEnabled', 'N/A'),
                'created_date_time': raw_response.get('createdDateTime', 'N/A'),
                'last_password_change': raw_response.get('lastPasswordChangeDateTime', 'N/A'),
                'password_policies': raw_response.get('passwordPolicies', 'N/A'),
                'assigned_licenses': [license.get('skuId', 'N/A') for license in raw_response.get('assignedLicenses', [])],
                'assigned_plans_count': len(raw_response.get('assignedPlans', [])),
                'about_me': raw_response.get('aboutMe', 'N/A')
            }

            return True, user_info

        except Exception as e:
            return False, {"error": str(e)}

    def _get_user_groups(self, user_identifier: str) -> Tuple[bool, Dict[str, Any]]:
        """Get user's group memberships"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_identifier}/memberOf?$select=id,displayName,description,groupTypes,securityEnabled,mailEnabled,isAssignableToRole"
            
            raw_response = GraphRequest().get(url=endpoint_url)

            if 'error' in raw_response:
                return False, {"error": f"Error {raw_response.get('error').get('code')}: {raw_response.get('error').get('message')}"}

            groups = []
            for group in raw_response:
                groups.append({
                    'id': group.get('id', 'N/A'),
                    'display_name': group.get('displayName', 'N/A'),
                    'description': group.get('description', 'N/A'),
                    'group_types': group.get('groupTypes', []),
                    'security_enabled': group.get('securityEnabled', 'N/A'),
                    'mail_enabled': group.get('mailEnabled', 'N/A'),
                    'is_assignable_to_role': group.get('isAssignableToRole', 'N/A')
                })

            return True, {
                'total_groups': len(groups),
                'groups': groups
            }

        except Exception as e:
            return False, {"error": str(e)}

    def _get_user_directory_roles(self, user_identifier: str) -> Tuple[bool, Dict[str, Any]]:
        """Get user's directory role assignments"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_identifier}/appRoleAssignments?$select=id,principalDisplayName,principalId,principalType,resourceDisplayName,resourceId,appRoleId"
            
            raw_response = GraphRequest().get(url=endpoint_url)

            if 'error' in raw_response:
                return False, {"error": f"Error {raw_response.get('error').get('code')}: {raw_response.get('error').get('message')}"}

            # Get directory role memberships
            dir_roles_url = f"https://graph.microsoft.com/v1.0/users/{user_identifier}/memberOf/microsoft.graph.directoryRole?$select=id,displayName,description,roleTemplateId"
            
            dir_roles_response = GraphRequest().get(url=dir_roles_url)
            
            directory_roles = []
            if not ('error' in dir_roles_response):
                for role in dir_roles_response:
                    directory_roles.append({
                        'id': role.get('id', 'N/A'),
                        'display_name': role.get('displayName', 'N/A'),
                        'description': role.get('description', 'N/A'),
                        'role_template_id': role.get('roleTemplateId', 'N/A')
                    })

            app_roles = []
            for assignment in raw_response:
                app_roles.append({
                    'assignment_id': assignment.get('id', 'N/A'),
                    'principal_display_name': assignment.get('principalDisplayName', 'N/A'),
                    'principal_id': assignment.get('principalId', 'N/A'),
                    'principal_type': assignment.get('principalType', 'N/A'),
                    'resource_display_name': assignment.get('resourceDisplayName', 'N/A'),
                    'resource_id': assignment.get('resourceId', 'N/A'),
                    'app_role_id': assignment.get('appRoleId', 'N/A')
                })

            return True, {
                'directory_roles': {
                    'total_roles': len(directory_roles),
                    'roles': directory_roles
                },
                'app_role_assignments': {
                    'total_assignments': len(app_roles),
                    'assignments': app_roles
                }
            }

        except Exception as e:
            return False, {"error": str(e)}

    def _get_user_app_assignments(self, user_identifier: str) -> Tuple[bool, Dict[str, Any]]:
        """Get user's application assignments"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_identifier}/appRoleAssignments?$select=id,appRoleId,principalDisplayName,resourceDisplayName,resourceId,createdDateTime"
            
            raw_response = GraphRequest().get(url=endpoint_url)

            if 'error' in raw_response:
                return False, {"error": f"Error {raw_response.get('error').get('code')}: {raw_response.get('error').get('message')}"}

            assignments = []
            for assignment in raw_response:
                assignments.append({
                    'assignment_id': assignment.get('id', 'N/A'),
                    'app_role_id': assignment.get('appRoleId', 'N/A'),
                    'principal_display_name': assignment.get('principalDisplayName', 'N/A'),
                    'resource_display_name': assignment.get('resourceDisplayName', 'N/A'),
                    'resource_id': assignment.get('resourceId', 'N/A'),
                    'created_date_time': assignment.get('createdDateTime', 'N/A')
                })

            return True, {
                'total_app_assignments': len(assignments),
                'assignments': assignments
            }

        except Exception as e:
            return False, {"error": str(e)}

    def _get_user_manager(self, user_identifier: str) -> Tuple[bool, Dict[str, Any]]:
        """Get user's manager information"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_identifier}/manager?$select=id,displayName,userPrincipalName,jobTitle,department"
            
            raw_response = GraphRequest().get(url=endpoint_url)

            if 'error' in raw_response:
                return False, {"error": f"Error {raw_response.get('error').get('code')}: {raw_response.get('error').get('message')}"}

            manager_info = {
                'id': raw_response.get('id', 'N/A'),
                'display_name': raw_response.get('displayName', 'N/A'),
                'upn': raw_response.get('userPrincipalName', 'N/A'),
                'job_title': raw_response.get('jobTitle', 'N/A'),
                'department': raw_response.get('department', 'N/A')
            }

            return True, manager_info

        except Exception as e:
            return False, {"error": str(e)}

    def _get_user_direct_reports(self, user_identifier: str) -> Tuple[bool, Dict[str, Any]]:
        """Get user's direct reports"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_identifier}/directReports?$select=id,displayName,userPrincipalName,jobTitle,department"
            
            raw_response = GraphRequest().get(url=endpoint_url)

            if 'error' in raw_response:
                return False, {"error": f"Error {raw_response.get('error').get('code')}: {raw_response.get('error').get('message')}"}

            reports = []
            for report in raw_response:
                reports.append({
                    'id': report.get('id', 'N/A'),
                    'display_name': report.get('displayName', 'N/A'),
                    'upn': report.get('userPrincipalName', 'N/A'),
                    'job_title': report.get('jobTitle', 'N/A'),
                    'department': report.get('department', 'N/A')
                })

            return True, {
                'total_direct_reports': len(reports),
                'reports': reports
            }

        except Exception as e:
            return False, {"error": str(e)}

    def _get_user_owned_objects(self, user_identifier: str) -> Tuple[bool, Dict[str, Any]]:
        """Get objects owned by the user"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_identifier}/ownedObjects?$select=id,displayName"
            
            raw_response = GraphRequest().get(url=endpoint_url)

            if 'error' in raw_response:
                return False, {"error": f"Error {raw_response.get('error').get('code')}: {raw_response.get('error').get('message')}"}

            owned_objects = []
            for obj in raw_response:
                owned_objects.append({
                    'id': obj.get('id', 'N/A'),
                    'display_name': obj.get('displayName', 'N/A'),
                    'object_type': obj.get('@odata.type', 'N/A')
                })

            return True, {
                'total_owned_objects': len(owned_objects),
                'objects': owned_objects
            }

        except Exception as e:
            return False, {"error": str(e)}

    def _get_user_registered_devices(self, user_identifier: str) -> Tuple[bool, Dict[str, Any]]:
        """Get devices registered by the user"""
        try:
            endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_identifier}/registeredDevices?$select=id,displayName,deviceId,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged"
            
            raw_response = GraphRequest().get(url=endpoint_url)

            if 'error' in raw_response:
                return False, {"error": f"Error {raw_response.get('error').get('code')}: {raw_response.get('error').get('message')}"}

            devices = []
            for device in raw_response:
                devices.append({
                    'id': device.get('id', 'N/A'),
                    'display_name': device.get('displayName', 'N/A'),
                    'device_id': device.get('deviceId', 'N/A'),
                    'operating_system': device.get('operatingSystem', 'N/A'),
                    'os_version': device.get('operatingSystemVersion', 'N/A'),
                    'trust_type': device.get('trustType', 'N/A'),
                    'is_compliant': device.get('isCompliant', 'N/A'),
                    'is_managed': device.get('isManaged', 'N/A')
                })

            return True, {
                'total_registered_devices': len(devices),
                'devices': devices
            }

        except Exception as e:
            return False, {"error": str(e)}

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "user_identifier": {
                "type": "str", 
                "required": True, 
                "default": None, 
                "name": "User UPN or Object ID", 
                "input_field_type": "text"
            }
        }