import re
import importlib
from core.Constants import *
from typing import List, Dict, Tuple, Optional

class Technique:
    """
    Represents an individual attack technique in the Halberd Attack Library.

    Attributes:
        technique_id (str): Unique identifier for the technique.
        name (str): Name of the technique.
        attack_surface (str): The attack surface this technique targets.
        file (str): Path to the Python file implementing this technique.
        description (str): Description of what the technique does.
        tactics (List[str]): List of tactics this technique is associated with.
        mitre_ids (List[str]): List of associated MITRE technique IDs.
        azure_matrix_ids (List[str]): List of associated Azure Threat Research Matrix IDs.
        inputs (List[Dict]): List of input parameters required by this technique.
        execution_status (Optional[bool]): Status of the last execution (None if not executed).
        raw_result (Optional[Dict]): Raw result from the last execution.
        pretty_response (Optional[Dict]): Formatted result from the last execution.
    """

    def __init__(self, technique_id: str, technique_data: Dict):
        """
        Initialize a Technique object.

        Args:
            technique_id (str): Unique identifier for the technique.
            technique_data (Dict): Dictionary containing technique details from MasterRecord.yml.
        """
        self.technique_id = technique_id
        self.name = technique_data.get('Name', '')
        self.attack_surface = technique_data.get('AttackSurface', '')
        self.file = technique_data.get('ExecutionPath', '')
        self.description = technique_data.get('Description', '')
        self.tactics = self._extract_tactics(technique_data)
        self.mitre_ids = self._extract_mitre_ids(technique_data)
        self.azure_matrix_ids = self._extract_azure_matrix_ids(technique_data)
        self.inputs: List[Dict] = []
        self.execution_status: Optional[bool] = None
        self.raw_result: Optional[Dict] = None
        self.pretty_response: Optional[Dict] = None
        self._load_technique_module()

    def _extract_tactics(self, technique_data: Dict) -> List[str]:
        """
        Extract tactics from the technique data.

        Args:
            technique_data (Dict): Dictionary containing technique details.

        Returns:
            List[str]: List of unique tactics associated with this technique.
        """
        mitre_data = technique_data.get('References', {}).get('MITRE', {})
        tactics = []
        for entry in mitre_data.values():
            tactics.extend(entry.get('Tactic', []))
        return list(set(tactics))

    def _extract_mitre_ids(self, technique_data: Dict) -> List[str]:
        """
        Extract MITRE technique IDs from the technique data.

        Args:
            technique_data (Dict): Dictionary containing technique details.

        Returns:
            List[str]: List of MITRE technique IDs associated with this technique.
        """
        mitre_data = technique_data.get('References', {}).get('MITRE', {})
        return list(mitre_data.keys())

    def _extract_azure_matrix_ids(self, technique_data: Dict) -> List[str]:
        """
        Extract Azure Threat Research Matrix IDs from the technique data.

        Args:
            technique_data (Dict): Dictionary containing technique details.

        Returns:
            List[str]: List of Azure Threat Research Matrix IDs associated with this technique.
        """
        azure_data = technique_data.get('References', {}).get('AzureThreatResearchMatrix', [])
        return [id for id in azure_data if id is not None]
    
    def _load_technique_module(self) -> None:
        """
        Load the main execution & input module for this technique.

        Raises:
            ImportError: If the module cannot be loaded.
        """
        try:
            execution_path = self.file

            exec_module_path = re.findall(r'[^\/\.]+', execution_path)
            exec_module = importlib.import_module(f"Techniques.{exec_module_path[0]}.{exec_module_path[1]}")
            self.technique_main = getattr(exec_module, "TechniqueMain")
            self.inputs = getattr(exec_module, "TechniqueInputSrc")

        except Exception as e:
            raise ImportError(f"Failed to load technique module: {e}")

    def execute(self, *kwargs) -> Tuple[bool, Optional[Dict], Optional[Dict]]:
        """
        Execute the technique with the provided parameters.

        Args:
            *kwargs: Keyword arguments required by the technique.

        Returns:
            Tuple[bool, Optional[Dict], Optional[Dict]]: 
                A tuple containing execution status, raw result, and pretty response.
        """
        self.execution_status, self.raw_result, self.pretty_response = self.technique_main(*kwargs)
        return self.execution_status, self.raw_result, self.pretty_response

    def status(self) -> Optional[bool]:
        """
        Get the status of the last execution.

        Returns:
            Optional[bool]: True if successful, False if failed, None if not executed.
        """
        return self.execution_status

    def pretty_result(self) -> Optional[Dict]:
        """
        Get the formatted result of the last execution.

        Returns:
            Optional[Dict]: Pretty formatted result, or None if not available.
        """
        return self.pretty_response

    def raw_response(self) -> Optional[Dict]:
        """
        Get the raw result of the last execution.

        Returns:
            Optional[Dict]: Raw result, or None if not available.
        """
        return self.raw_result