
from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry

from typing import Dict, Any, Tuple

from core.gcp.gcp_access import GCPAccess
# from google.cloud import resourcemanager_v3
from googleapiclient import discovery

@TechniqueRegistry.register
class GCPEnumerateProjects(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1526",
                technique_name="Cloud Service Discovery",
                tactics=["Discovery"],
            )
        ]

        technique_references = [
            TechniqueReference(ref_title = "GCP Resource Manager Documentation", ref_link = "https://cloud.google.com/resource-manager/docs/quickstarts"),
            TechniqueReference(ref_title = "GCP Resource Manager API", ref_link = "https://cloud.google.com/resource-manager/reference/rest/v3/projects/list")
        ]

        super().__init__("Enumerate Projects", "Enumerate Google Cloud Platform projects accessible with the current credentials. This technique leverages the GCP Resource Manager API to list all projects that the authenticated user or service account has access to. By enumerating projects, attackers can identify potential targets for further exploitation, assess the scope of their access, and gather information about the cloud environment. The technique handles API interactions, manages pagination for large result sets, and formats the output for easy analysis.", mitre_techniques=mitre_techniques, references=technique_references)

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            org_id: str = kwargs.get('organization_id')
            folder_id: str = kwargs.get('folder_id')
            filter: str
            project_list: list

            if org_id:
                filter = f"parent.type:organization parent.id:{org_id}"
            elif folder_id:
                filter = f"parent.type:folder parent.id:{folder_id}"
            elif folder_id and org_id:
                filter = f"parent.type:folder parent.id:{folder_id}"
            else:
                filter = None
            manager = GCPAccess()
            manager.get_current_access()
            credential = manager.credential
            service = discovery.build('cloudresourcemanager', 'v1', credentials=credential)
            service_request = service.projects().list(filter=filter) if filter else service.projects().list()
            response = service_request.execute()

            if 'projects' in response:
                project_list = []
                for project in response['projects']:
                    project_list.append({
                        "project_id": project.get("projectId"),
                        "name": project.get("name"),
                        "state": project.get("lifecycleState"),
                        "project_number": project.get("projectNumber"),
                        "parent": project.get("parent")
                    })
            else:
                project_list = []

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully enumerated {len(project_list)} projects.",
                "value": {
                    "project_found": len(project_list),
                    "projects": project_list
                }
                
            }

        # except google.api_core.exceptions.GoogleAPIError as e:
        #     return ExecutionStatus.FAILURE, {
        #         "error": {"GoogleAPIError": str(e)},
        #         "message": {"GoogleAPIError": str(e)}
        #     }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": f"Failed to enumerate projects: {str(e)}"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
            return {
                "organization_id": {
                     "type": "str",
                     "required": False,
                     "default": None,
                     "name": "Organization ID",
                     "input_field_type": "text",
                },
                "folder_id": {
                     "type": "str",
                     "required": False,
                     "default": None,
                     "name": "Folder ID",
                     "input_field_type": "text",
                },
            }