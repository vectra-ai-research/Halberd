import yaml
from core.Constants import *
from typing import List, Dict, Optional
from core.technique.technique import Technique

class HalberdAttackLibrary:
    """
    Represents the entire Halberd Attack Library.

    This class allows listing, accessing various details and executing attack techniques.

    Attributes:
        techniques (Dict[str, Technique]): Dictionary of all loaded techniques.
    """

    def __init__(self, master_record_path: str = MASTER_RECORD_FILE):
        """
        Initialize the HalberdAttackLibrary.

        Args:
            master_record_path (str): Path to the MasterRecord.yml file.
        """
        self.techniques: Dict[str, Technique] = {}
        self.load_techniques(master_record_path)

    def load_techniques(self, master_record_path: str) -> None:
        """
        Load all techniques from the MasterRecord.yml file.

        Args:
            master_record_path (str): Path to the MasterRecord.yml file.

        Raises:
            FileNotFoundError: If the MasterRecord.yml file is not found.
            yaml.YAMLError: If there's an error parsing the YAML file.
        """
        try:
            with open(master_record_path, 'r') as file:
                master_record = yaml.safe_load(file)
            
            for technique_id, technique_data in master_record.items():
                if technique_id != "Sample record":
                    self.techniques[technique_id] = Technique(technique_id, technique_data)
        except FileNotFoundError:
            raise FileNotFoundError(f"MasterRecord.yml not found at {master_record_path}")
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Error parsing MasterRecord.yml: {e}")

    def list_techniques(
            self, 
            attack_surface: Optional[str] = None, 
            tactic: Optional[str] = None, 
            mitre_id: Optional[str] = None, 
            azure_matrix_id: Optional[str] = None) -> List[str]:
        """
        List techniques with optional filters for various criterias.

        Args:
            attack_surface (Optional[str]): Filter techniques by this attack surface.
            tactic (Optional[str]): Filter techniques by this tactic.
            mitre_id (Optional[str]): Filter techniques by this MITRE technique ID.
            azure_matrix_id (Optional[str]): Filter techniques by this Azure Threat Research Matrix ID.

        Returns:
            List[str]: List of technique IDs matching the filters.
        """
        filtered_techniques = self.techniques.values()
        
        if attack_surface:
            filtered_techniques = [t for t in filtered_techniques if t.attack_surface == attack_surface]
        
        if tactic:
            filtered_techniques = [t for t in filtered_techniques if tactic in t.tactics]
        
        if mitre_id:
            filtered_techniques = [t for t in filtered_techniques if mitre_id in t.mitre_ids]
        
        if azure_matrix_id:
            filtered_techniques = [t for t in filtered_techniques if azure_matrix_id in t.azure_matrix_ids]
        
        return [t.technique_id for t in filtered_techniques]

    def get_technique(self, technique_id: str) -> Optional[Technique]:
        """
        Get a specific technique by its ID.

        Args:
            technique_id (str): The ID of the technique to retrieve.

        Returns:
            Optional[Technique]: The requested Technique object, or None if not found.
        """
        return self.techniques.get(technique_id)

    @property
    def attack_surfaces(self) -> List[str]:
        """
        Get a list of all unique attack surfaces in the library.

        Returns:
            List[str]: List of unique attack surfaces.
        """
        return list(set(technique.attack_surface for technique in self.techniques.values()))