import yaml
import re
import csv
import base64
import os
import time
import copy
import uuid
from pathlib import Path
from datetime import datetime
from core.Constants import *
from typing import List, Dict, Any, Optional, Union
from core.playbook.playbook_error import PlaybookError
from core.playbook.playbook_step import PlaybookStep
from attack_techniques.technique_registry import TechniqueRegistry

class Playbook:
    """Creates, modifies, executes and manages Halberd playbook"""
    REQUIRED_FIELDS = ['PB_Name', 'PB_Author', 'PB_Creation_Date', 'PB_Description', 'PB_Sequence']

    def __init__(self, pb_file_name: str):
        self.yaml_file = pb_file_name
        self.yaml_file_path = AUTOMATOR_PLAYBOOKS_DIR + "/" + pb_file_name

        pb_config_file = AUTOMATOR_PLAYBOOKS_DIR + "/" + pb_file_name
        with open(pb_config_file, "r") as pb_config_data:
            self.data = yaml.safe_load(pb_config_data)

        # self.data = yaml.safe_load(yaml_content)
        self.steps = len(self.data['PB_Sequence'])
        self._status = "Not started"
    
    @classmethod
    def create_new(cls, name: str, author: Optional[str] = None, description: Optional[str] = None, references: Optional[List[str]] = None) -> 'Playbook':
        """
        Create a new playbook from scratch.
        
        :param name: Name of the playbook
        :param author: Author of the playbook (optional)
        :param description: Description of the playbook (optional)
        :param references: List of references for the playbook (optional)
        :return: A new Playbook instance
        :raises PlaybookError: If there's an error in creating the playbook
        """
        try:
            # Validate input
            if not name:
                raise ValueError("Playbook name cannot be empty")
            if not re.match(r'^[\w\-\s]+$', name):
                raise ValueError("Playbook name contains invalid characters. Use only letters, numbers, spaces, hyphens, and underscores.")
            
            # Generate file name from playbook name
            pb_file_name = name.replace(' ', '_') + '.yml'
            
            # Check if file already exists
            if os.path.exists(f"{AUTOMATOR_PLAYBOOKS_DIR}/{pb_file_name}"):
                raise FileExistsError(f"A playbook with the name '{pb_file_name}' already exists.")
            
            new_playbook_data = {
                'PB_Name': name,
                'PB_Author': author or 'Unknown',
                'PB_Creation_Date': time.strftime("%m-%d-%Y"),
                'PB_Description': description or '',
                'PB_References': references or [],
                'PB_Sequence': {}
            }
            
            # Try to create and write to the file
            try:
                with open(f"{AUTOMATOR_PLAYBOOKS_DIR}/{pb_file_name}", 'w') as file:
                    yaml.dump(new_playbook_data, file, default_flow_style=False)
            except IOError as e:
                raise PlaybookError(f"Error writing playbook to file: {e}")
            
            return cls(pb_file_name)
        
        except (ValueError, FileExistsError, PlaybookError) as e:
            raise PlaybookError(f"Error creating playbook: {str(e)}")
        except Exception as e:
            raise PlaybookError(f"Unexpected error occurred while creating playbook: {str(e)}")

    @classmethod
    def import_playbook(cls, playbook_content: str) -> 'Playbook':
        """
        Import a playbook from a base64 encoded string content and save it to the app-specific location.
        
        :param playbook_content: Base64 encoded string content of the playbook
        :return: A new Playbook instance
        :raises PlaybookError: If there's an error in importing the playbook
        """
        try:
            # Extract the base64 encoded content
            content_match = re.match(r'data:application/x-yaml;base64,(.+)', playbook_content)
            if not content_match:
                raise PlaybookError("Invalid base64 content format")
            
            base64_yaml = content_match.group(1)
            
            # Decode the base64 content
            try:
                yaml_content = base64.b64decode(base64_yaml).decode('utf-8')
            except Exception as e:
                raise PlaybookError(f"Error decoding base64 content: {str(e)}")
            
            # Parse the YAML content
            try:
                playbook_data = yaml.safe_load(yaml_content)
            except yaml.YAMLError as e:
                raise PlaybookError(f"Error parsing YAML content: {str(e)}")
            
            # Validate playbook structure
            cls._validate_playbook_structure(playbook_data)
            
            # Ensure app playbook directory exists
            os.makedirs(AUTOMATOR_PLAYBOOKS_DIR, exist_ok=True)
            
            # Generate a unique file name in app-specific directory
            file_name = f"{playbook_data['PB_Name'].replace(' ', '_')}_{uuid.uuid4().hex[:8]}.yml"
            new_file_path = os.path.join(AUTOMATOR_PLAYBOOKS_DIR, file_name)
            
            # Write the content to the new file
            with open(new_file_path, 'w') as file:
                yaml.dump(playbook_data, file, default_flow_style=False)
            
            print(f"Playbook imported and saved to: {new_file_path}")
            return cls(file_name)
        
        except PlaybookError as e:
            raise e
        except Exception as e:
            raise PlaybookError(f"Unexpected error occurred while importing playbook: {str(e)}")

    @classmethod
    def _validate_playbook_structure(cls, playbook_data: Dict[str, Any]):
        """
        Validate the structure of the playbook data.
        
        :param playbook_data: Dictionary containing playbook data
        :raises PlaybookError: If the playbook structure is invalid
        """
        # Check for required fields
        for field in cls.REQUIRED_FIELDS:
            if field not in playbook_data:
                raise PlaybookError(f"Missing required field: {field}")
        
        # Validate PB_Sequence
        if not isinstance(playbook_data['PB_Sequence'], dict):
            raise PlaybookError("PB_Sequence must be a dictionary")
        
        for step_num, step_data in playbook_data['PB_Sequence'].items():
            if not isinstance(step_data, dict):
                raise PlaybookError(f"Playbook Data Incorrect : Step {step_num} must be a dictionary")
            if 'Module' not in step_data:
                raise PlaybookError(f"Playbook Data Incorrect : Step {step_num} is missing 'Module' field")
            if 'Params' not in step_data:
                raise PlaybookError(f"Playbook Data Incorrect : Step {step_num} is missing 'Params' field")
            if 'Wait' not in step_data:
                raise PlaybookError(f"Playbook Data Incorrect : Step {step_num} is missing 'Wait' field")
            
    def step(self, step_number: Optional[int] = None) -> Union[PlaybookStep, List[PlaybookStep]]:
        """
        Get a specific step or all steps of the playbook.
        
        :param step_number: If provided, return the specific step. If None, return all steps.
        :return: A single Step object or a list of Step objects.
        """
        if step_number is not None:
            if 1 <= step_number <= self.steps:
                step_data = self.data['PB_Sequence'][step_number]
                return PlaybookStep(step_data['Module'], step_data['Params'], step_data['Wait'])
            else:
                raise ValueError(f"Step number {step_number} is out of range")
        else:
            return [PlaybookStep(step_data['Module'], step_data['Params'], step_data['Wait']) 
                    for step_data in self.data['PB_Sequence'].values()]

    def add_step(self, new_step: PlaybookStep, step_no: Optional[int] = None) -> None:
        step_dict = {
            'Module': new_step.module,
            'Params': new_step.params,
            'Wait': new_step.wait if new_step.wait else 0
        }

        if step_no is None:
            self.data['PB_Sequence'][self.steps + 1] = step_dict
            self.steps += 1
        else:
            if 1 <= step_no <= self.steps + 1:
                # Shift existing steps
                for i in range(self.steps, step_no - 1, -1):
                    self.data['PB_Sequence'][i + 1] = self.data['PB_Sequence'][i]
                self.data['PB_Sequence'][step_no] = step_dict
                self.steps += 1
            else:
                raise ValueError(f"Step number {step_no} is out of range")
            
        self.save()  # save playbook after adding a step

    def execute(self, step_number: Optional[int] = None) -> None:
        """
        Execute the entire playbook or a specific step.
        
        :param step_number: If provided, execute only this step. Otherwise, execute the entire playbook.
        """
        # Create automation run folder
        execution_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        execution_folder_name = f"{self.name}_{execution_time}"
        execution_folder_path = os.path.join(AUTOMATOR_OUTPUT_DIR, execution_folder_name)
        os.makedirs(execution_folder_path)

        # Store current execution config
        execution_config_file_path = os.path.join(execution_folder_path, "Execution_Config.yml")
        with open(execution_config_file_path, 'w') as file:
            # Write the YAML data to the file
            yaml.dump(self.data['PB_Sequence'], file, default_flow_style=False)

        execution_report_file_path = os.path.join(execution_folder_path, "Report.csv")

        # Execute
        if step_number is not None:
            if 1 <= step_number <= self.steps:
                # Log execution start time
                execution_start_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                
                # Execute playbook step
                execution_result = self._execute_step(step_number)
                self.generate_report(module_tid = self.step(step_number).module, execution_start_time = execution_start_time, execution_result = execution_result, execution_folder_path = execution_folder_path)
            else:
                raise ValueError(f"Step number {step_number} is out of range")
        else:
            self._status = "Running"
            for step_no in range(1, self.steps + 1):
                # Log execution start time
                execution_start_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                # Execute playbook step
                execution_result = self._execute_step(step_no)
                # Generate report
                self.generate_report(module_tid = self.step(step_no).module, execution_start_time = execution_start_time, execution_result = execution_result, execution_folder_path = execution_folder_path)
                # Start wait to execute next step
                time.sleep(self.step(step_no).wait if self.step(step_no).wait else 0)

            # Update playbook run status
            self._status = "Completed"

    def _execute_step(self, step_number: int):
        """
        Execute a single step of the playbook.
        
        :param step_number: The step number to execute.
        """

        step = self.step(step_number)
        print(f"Executing step {step_number}: {step.module}")

        # Technique
        t_id = step.module
    
        # Technique input
        step_input = step.params

        # Execute technique
        technique = TechniqueRegistry.get_technique(t_id)

        output = technique().execute(**step_input)

        return output
    
    def generate_report(self, module_tid : str, execution_start_time, execution_result, execution_folder_path : str, save_output : Optional[bool] = True) -> None:
        """
        Generate report of playbook step execution.
        
        :param module_tid: The id of the module being executed.
        :param execution_start_time: The start time of step execution.
        :param execution_result: The result of playbook step execution.
        :param execution_folder_path: The path of current playbook execution folder.
        """
        execution_report_file_path = os.path.join(execution_folder_path, "Report.csv")
        module_output_file = os.path.join(execution_folder_path, f"Result_{module_tid}.txt")

        # Check if technique output is in the expected tuple format (success, response)
        if isinstance(execution_result, tuple) and len(execution_result) == 2:
            result, response = execution_result
        else:
            response = execution_result

        # Create summary report
        try:
            if result.value == "success":
                self._playbook_create_csv_report(execution_report_file_path, execution_start_time, module_tid, "success")
            else:
                self._playbook_create_csv_report(execution_report_file_path, execution_start_time, module_tid, "failed")
        except:
            self._playbook_create_csv_report(execution_report_file_path, execution_start_time, module_tid, "failed")

        # Store responses
        if save_output:
            # Save step/module execution output
            with open(module_output_file, 'w') as file:
                # write result data to the file
                file.write(str(response))

    def _playbook_create_csv_report(self, report_file_name, time_stamp, module, result):
        """
        create and write to execution summary report in CSV format
        
        :param report_file_name: Filename of the report to be generated.
        :param time_stamp: The start time of step execution.
        :param module: The module ID.
        :param result: The result of playbook step execution.
        """

        # define headers
        headers = ["Time_Stamp", "Module", "Result"]

        if Path(f"{AUTOMATOR_DIR}/{report_file_name}").exists():
            pass
        else:
            # create new report file with headers
            f = open(report_file_name,"a")
            report_input = {"Time_Stamp":"Time_Stamp", "Module":"Module", "Result":"Result"}
            write_log = csv.DictWriter(f, fieldnames= headers)
            write_log.writerow(report_input)

        # write execution information to report
        report_input = {"Time_Stamp": time_stamp, "Module": module, "Result": result}
        write_log = csv.DictWriter(f, fieldnames= headers)
        write_log.writerow(report_input)

    def status(self) -> str:
        return self._status
    
    def save(self, new_file: Optional[str] = None) -> None:
        """
        Save the current playbook configuration to a YAML file.
        If new_file is provided, save to a new file. Otherwise, overwrite the original file.
        """
        if new_file:
            save_file = os.path.join(AUTOMATOR_PLAYBOOKS_DIR,new_file)
        else:
            save_file = self.yaml_file_path
        
        # Update the creation date to the current date
        self.data['PB_Creation_Date'] = time.strftime("%m-%d-%Y")
        
        with open(save_file, 'w') as file:
            yaml.dump(self.data, file, default_flow_style=False)
        
        print(f"Playbook saved to {save_file}")
        
        # Update the yaml_file attribute if a new file was created
        if new_file:
            self.yaml_file = new_file

    def export(self, export_file: str, include_params: bool = False):
        """
        Export the playbook to a new YAML file, optionally excluding parameter values.
        
        :param export_file: The filename to export the playbook to.
        :param include_params: If True, include parameter values. If False, replace with placeholders.
        """
        export_data = copy.deepcopy(self.data)
        export_file_path = os.path.join(AUTOMATOR_EXPORTS_DIR, export_file)
        if not include_params:
            # Mask all values in playbook steps
            for step in export_data['PB_Sequence'].values():
                if step['Params']:
                    step['Params'] = {key: "<masked>" for key in step['Params']}
        
        # Update the creation date to the current date
        export_data['PB_Creation_Date'] = time.strftime("%m-%d-%Y")
        
        with open(export_file_path, 'w') as file:
            yaml.dump(export_data, file, default_flow_style=False)
        
        return export_file_path

    @property
    def name(self) -> str:
        return self.data['PB_Name']

    @property
    def author(self) -> str:
        return self.data['PB_Author']

    @property
    def creation_date(self) -> str:
        return self.data['PB_Creation_Date']

    @property
    def description(self) -> str:
        return self.data['PB_Description']
    
    @property
    def references(self) -> List[str]:
        return self.data.get('PB_References', [])