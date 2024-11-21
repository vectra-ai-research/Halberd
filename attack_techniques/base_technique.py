from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, Tuple, List

class ExecutionStatus(Enum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"

class MitreTechnique:
    def __init__(self, technique_id: str, technique_name: str, tactics: List[str], 
                 sub_technique_name: str = None):
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.tactics = tactics
        self.sub_technique_name = sub_technique_name
        if sub_technique_name:
            self.mitre_url = f"https://attack.mitre.org/techniques/{technique_id.replace('.','/')}/"
        else:
            self.mitre_url = f"https://attack.mitre.org/techniques/{technique_id}/"

class AzureTRMTechnique:
    def __init__(self, technique_id: str, technique_name: str, tactics: List[str], 
                 sub_technique_name: str = None):
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.tactics = tactics
        self.sub_technique_name = sub_technique_name
        if sub_technique_name:
            self.azure_trm_url = f"https://microsoft.github.io/Azure-Threat-Research-Matrix/{tactics[0].replace(' ', '')}/{technique_id.split('.')[0]}/{technique_id.replace('.','-')}/"
        else:
            self.azure_trm_url = f"https://microsoft.github.io/Azure-Threat-Research-Matrix/{tactics[0].replace(' ', '')}/{technique_id.split('.')[0]}/{technique_id.split('.')[0]}/"

class TechniqueReference:
    """
    Class for defining a single reference for the technique
    """
    def __init__(self, ref_title: str, ref_link: str):
        self.title = ref_title
        self.link = ref_link

class TechniqueNote:
    """
    List of notes and any additional information related to the technique
    """
    def __init__(self, note: str):
        self.note = note

class BaseTechnique(ABC):
    def __init__(self, name: str, description: str, mitre_techniques: List[MitreTechnique], azure_trm_techniques: List[AzureTRMTechnique] = None, references: List[TechniqueReference] = None, notes: List[TechniqueNote] = None):
        self.name = name
        self.description = description
        self.mitre_techniques = mitre_techniques
        self.azure_trm_techniques = azure_trm_techniques
        self.references = references
        self.notes = notes

    @abstractmethod
    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        """
        Execute the technique and return the execution status and results.
        
        Returns:
            A tuple containing:
            - ExecutionStatus: The status of the execution
            - Dict[str, Any]: The results of the technique execution
        """
        pass

    @abstractmethod
    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        """Return the parameters required for this technique."""
        pass

    def validate_parameters(self, params: Dict[str, Any]) -> None:
        """Validate the provided parameters against the required parameters."""
        required_params = self.get_parameters()
        for param, config in required_params.items():
            if config.get('required', False) and param not in params:
                raise ValueError(f"Missing required parameter: {param}")
        
        for param, value in params.items():
            if param not in required_params:
                raise ValueError(f"Unknown parameter: {param}")
            
            param_type = required_params[param].get('type')
            
            if param_type and isinstance(value, eval(param_type)):
                pass
            else:
                # Raise error if input is not in expected format or not none
                if value:
                    raise TypeError(f"Invalid type for parameter {param}. Expected {param_type}, got {type(value)}")
                else:
                    pass
    
    def get_mitre_info(self) -> List[Dict[str, Any]]:
        """Returns a list of dictionaries containing MITRE information for all associated techniques"""
        return [
            {
                "technique_id": tech.technique_id,
                "technique_name": tech.technique_name,
                "tactics": tech.tactics,
                "sub_technique_name": tech.sub_technique_name,
                "mitre_url": tech.mitre_url
            } for tech in self.mitre_techniques
        ]
    
    def get_azure_trm_info(self) -> List[Dict[str, Any]]:
        """Returns a list of dictionaries containing Azure Threat Research Matrix information for all associated techniques"""
        return [
            {
                "technique_id": tech.technique_id,
                "technique_name": tech.technique_name,
                "tactics": tech.tactics,
                "sub_technique_name": tech.sub_technique_name,
                "azure_trm_url": tech.azure_trm_url
            } for tech in self.azure_trm_techniques
        ]