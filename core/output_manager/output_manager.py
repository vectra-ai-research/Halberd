import os
import json
import uuid
from datetime import datetime
from typing import Any, Optional, Dict, List
from pathlib import Path
from core.Constants import TECHNIQUE_OUTPUT_DIR

class OutputManager:
    """Manages technique output storage and retrieval with event tracking"""
    
    def __init__(self, base_output_dir: str = TECHNIQUE_OUTPUT_DIR):
        self.base_output_dir = base_output_dir
        self.event_index_file = os.path.join(base_output_dir, "event_index.json")
        self._check_base_dir()
        self._load_event_index()

    def _check_base_dir(self) -> None:
        """Ensures base output directory exists"""
        os.makedirs(self.base_output_dir, exist_ok=True)

    def _load_event_index(self) -> None:
        """Loads or initializes the event index"""
        try:
            if os.path.exists(self.event_index_file):
                with open(self.event_index_file, 'r') as f:
                    self.event_index = json.load(f)
            else:
                self.event_index = {}
        except Exception as e:
            print(f"Error loading event index, creating new: {str(e)}")
            self.event_index = {}

    def _save_event_index(self) -> None:
        """Saves the current event index"""
        try:
            with open(self.event_index_file, 'w') as f:
                json.dump(self.event_index, f, indent=2)
        except Exception as e:
            print(f"Error saving event index: {str(e)}")

    def store_technique_output(self, data: Any, technique_name: str, event_id: Optional[str] = None) -> Optional[str]:
        """
        Stores technique output data with event tracking.
        
        Args:
            data: The data to store (can be string, list, dict, or nested combinations)
            technique_name: Name of the technique generating the output
            event_id: Optional event ID (generated if not provided)
            
        Returns:
            str: Event ID if successful, None if failed
            
        Example:
            output_manager = OutputManager()
            event_id = output_manager.store_technique_output(
                {"scan_results": ["finding1"]}, 
                "AzureAssignRole"
            )
        """
        try:
            # Generate or use provided event ID
            event_id = event_id or str(uuid.uuid4())
            timestamp = datetime.now()
            
            # Create output directory structure
            technique_dir = os.path.join(self.base_output_dir, technique_name)
            output_path = Path(technique_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Generate filename with event ID
            filename = f"{technique_name}_{timestamp.strftime('%Y%m%d_%H%M%S')}_{event_id}.json"
            file_path = output_path / filename

            # Prepare metadata wrapper
            output_data = {
                "event_id": event_id,
                "technique": technique_name,
                "timestamp": timestamp.isoformat(),
                "data": data
            }
            
            # Write data
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, default=str, ensure_ascii=False)
            
            # Update event index
            self.event_index[event_id] = {
                "technique": technique_name,
                "timestamp": timestamp.isoformat(),
                "filepath": str(file_path)
            }
            self._save_event_index()
            
            return event_id
        
        except Exception as e:
            print(f"Error storing technique output: {str(e)}")
            return None

    def get_output_by_event_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves technique output data by event ID.
        
        Args:
            event_id: The event ID to look up
            
        Returns:
            The stored data if found, None if not found or error
            
        Example:
            output_manager = OutputManager()
            data = output_manager.get_output_by_event_id("1234-5678-90ab")
        """
        try:
            if event_id not in self.event_index:
                print(f"Event ID {event_id} not found")
                return None
                
            filepath = self.event_index[event_id]["filepath"]
            return self.read_technique_output(filepath)
            
        except Exception as e:
            print(f"Error retrieving output for event {event_id}: {str(e)}")
            return None

    def list_events(self, 
                   technique_name: Optional[str] = None, 
                   start_date: Optional[str] = None, 
                   end_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Lists stored events with optional filtering.
        
        Args:
            technique_name: Filter by technique name
            start_date: Filter by start date (ISO format)
            end_date: Filter by end date (ISO format)
            
        Returns:
            List of matching events with their metadata
            
        Example:
            output_manager = OutputManager()
            events = output_manager.list_events(
                technique_name="azure_scan_storage",
                start_date="2024-01-01"
            )
        """
        events = []
        for event_id, metadata in self.event_index.items():
            if technique_name and metadata["technique"] != technique_name:
                continue
                
            if start_date and metadata["timestamp"] < start_date:
                continue
                
            if end_date and metadata["timestamp"] > end_date:
                continue
                
            events.append({
                "event_id": event_id,
                **metadata
            })
            
        return sorted(events, key=lambda x: x["timestamp"], reverse=True)

    def read_technique_output(self, filepath: str) -> Optional[Dict[str, Any]]:
        """
        Reads technique output data from a JSON file.
        
        Args:
            filepath: Path to the JSON output file
            
        Returns:
            The stored data structure if successful, None if failed
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading technique output: {str(e)}")
            return None