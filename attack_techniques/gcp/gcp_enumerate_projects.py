
from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote, TechniqueReference
from ..technique_registry import TechniqueRegistry

from typing import Dict, Any, Tuple

from core.gcp.gcp_access import GCPAccess
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
            
            # Validate empty strings
            if org_id and org_id.strip() == "":
                org_id = None
            if folder_id and folder_id.strip() == "":
                folder_id = None
            
            filter_by_folder: str = None
            filter_by_org: str = None
            project_list = []

            if org_id:
                filter_by_org = f"parent.type:organization parent.id:{org_id}"
            if folder_id:
                filter_by_folder = f"parent.type:folder parent.id:{folder_id}"
            manager = GCPAccess()
            manager.get_current_access()
            credential = manager.credential
            service = discovery.build('cloudresourcemanager', 'v1', credentials=credential)
            request_by_org = service.projects().list(filter=filter_by_org) if org_id else None
            request_by_folder = service.projects().list(filter=filter_by_folder) if folder_id else None
            
            if org_id and folder_id:
                response_by_folder = request_by_folder.execute()
                response_by_org = request_by_org.execute()
                # Combine projects from both responses without duplicates
                projects = []
                seen_project_ids = set()
                
                for resp in [response_by_org, response_by_folder]:
                    if 'projects' in resp:
                        for project in resp['projects']:
                            project_id = project.get("projectId")
                            if project_id not in seen_project_ids:
                                projects.append(project)
                                seen_project_ids.add(project_id)
                
                response = {'projects': projects}
            elif org_id:
                response = request_by_org.execute()
            elif folder_id:
                response = request_by_folder.execute()
            else:
                response = service.projects().list().execute()
            

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