from typing import Type, Dict, Optional, List, Set
from .base_technique import BaseTechnique
import os

class TechniqueRegistry:
    _techniques: Dict[str, Type[BaseTechnique]] = {}
    _categories = ['azure', 'entra_id', 'aws', 'm365']
    _base_path = os.path.dirname(__file__)

    @classmethod
    def register(cls, technique_class: Type[BaseTechnique]) -> Type[BaseTechnique]:
        cls._techniques[technique_class.__name__] = technique_class
        return technique_class

    @classmethod
    def get_technique(cls, name: str) -> Type[BaseTechnique]:
        technique = cls._techniques.get(name)
        if not technique:
            raise ValueError(f"Technique not found: {name}")
        return technique

    @classmethod
    def list_techniques(cls, category: Optional[str] = None) -> Dict[str, Type[BaseTechnique]]:
        if category is None:
            return cls._techniques
        
        if category not in cls._categories:
            raise ValueError(f"Invalid category. Must be one of {cls._categories}")
        
        return {name: tech for name, tech in cls._techniques.items() 
                if cls.get_technique_category(name) == category}
    
    @classmethod
    def list_tactics(cls, category: Optional[str] = None) -> List[str]:
        techniques = cls.list_techniques(category)
        tactics: Set[str] = set()
        
        for tech_class in techniques.values():
            technique = tech_class()
            for mitre_technique in technique.mitre_techniques:
                tactics.update(mitre_technique.tactics)
        
        return sorted(list(tactics))
    
    @classmethod
    def get_technique_category(cls, technique_name: str) -> Optional[str]:
        technique_class = cls._techniques.get(technique_name)
        if not technique_class:
            return None
        
        technique_source = technique_class.__module__
        source_breakdown = technique_source.split(".")
        if len(source_breakdown)>=3 and source_breakdown[1] in cls._categories:
            return source_breakdown[1]
        
        return None