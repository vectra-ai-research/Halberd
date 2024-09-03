from core.Constants import *
from typing import List, Any, Optional

class PlaybookStep:
    """Defines a step in the playbook"""
    def __init__(self, module: str, params: Optional[List[Any]], wait: Optional[int]):
        self.module = module
        self.params = params if params is not None else []
        self.wait = wait