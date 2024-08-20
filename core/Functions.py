import yaml
import re
import csv
import importlib
import base64
import os
import sys
import shutil
import time
import copy
import uuid
from datetime import datetime
from pathlib import Path
from dash import html, dcc
import dash_bootstrap_components as dbc
from core.Constants import *
from dash_iconify import DashIconify
from typing import List, Dict, Any, Optional, Union

class MasterRecord:
    def __init__(self):
        # load the MasterRecord.yml file
        with open(MASTER_RECORD_FILE, 'r') as file:
            master_record = yaml.safe_load(file)
        
        self.data = master_record

        self.entra_id = {}
        self.m365 = {}
        self.aws = {}
        self.azure = {}

        techniques_list = []
        entra_id_techniques_list = []
        m365_techniques_list = []
        aws_techniques_list = []
        azure_techniques_list = []

        for technique in master_record:
            techniques_list.append(technique)

            if str(technique).startswith("EntraID"):
                self.entra_id[technique] = master_record[technique]
                entra_id_techniques_list.append(technique)
            elif str(technique).startswith("M365"):
                self.m365[technique] = master_record[technique]
                m365_techniques_list.append(technique)
            elif str(technique).startswith("AWS"):
                self.aws[technique] = master_record[technique]
                aws_techniques_list.append(technique)
            elif str(technique).startswith("Azure"):
                self.azure[technique] = master_record[technique]
                azure_techniques_list.append(technique)

        self.list_all_techniques = techniques_list
        self.list_m365_techniques = m365_techniques_list
        self.list_entraid_techniques = entra_id_techniques_list
        self.list_aws_techniques = aws_techniques_list
        self.list_azure_techniques = azure_techniques_list

        self.count_all_techniques = len(techniques_list)
        self.count_m365_techniques = len(m365_techniques_list)
        self.count_entraid_techniques = len(entra_id_techniques_list)
        self.count_aws_techniques = len(aws_techniques_list)
        self.count_azure_techniques = len(azure_techniques_list)

class PlaybookError(Exception):
    """Custom exception class for Playbook-related errors."""
    pass

class PlaybookStep:
    def __init__(self, module: str, params: Optional[List[Any]], wait: Optional[int]):
        self.module = module
        self.params = params if params is not None else []
        self.wait = wait

class Playbook:
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

        module_tid = step.module
        '''technique input'''
        technique_input = step.params

        '''technique execution'''
        techniques_info = MasterRecord().data
        execution_path = techniques_info[module_tid]['ExecutionPath']

        exec_module_path = re.findall(r'[^\/\.]+', execution_path)
        exec_module = importlib.import_module(f"Techniques.{exec_module_path[0]}.{exec_module_path[1]}")
        TechniqueMainFunction = getattr(exec_module, "TechniqueMain")

        if technique_input == None:
            technique_response = TechniqueMainFunction()
        else:
            technique_response = TechniqueMainFunction(*technique_input)

        return technique_response
    
    def generate_report(self, module_tid, execution_start_time, execution_result, execution_folder_path, save_output = True) -> None:
        """
        Generate report of playbook step execution.
        
        :param module_tid: The id of the module being executed.
        :param execution_start_time: The start time of step execution.
        :param execution_result: The result of playbook step execution.
        :param execution_folder_path: The path of current playbook execution folder.
        """
        execution_report_file_path = os.path.join(execution_folder_path, "Report.csv")
        module_output_file = os.path.join(execution_folder_path, f"Result_{module_tid}.txt")

        # check if technique output is in the expected tuple format (success, raw_response, pretty_response)
        if isinstance(execution_result, tuple) and len(execution_result) == 3:
            success, raw_response, pretty_response = execution_result
            # parse output
            if pretty_response != None:
                response = pretty_response
            else:
                response = raw_response
        else:
            response = execution_result

        # Create summary report
        try:
            if success == True:
                PlaybookCreateCSVReport(execution_report_file_path, execution_start_time, module_tid, "success")
            else:
                PlaybookCreateCSVReport(execution_report_file_path, execution_start_time, module_tid, "failed")
        except:
            PlaybookCreateCSVReport(execution_report_file_path, execution_start_time, module_tid, "failed")

        # Store responses
        if save_output:
            # Save step/module execution output
            with open(module_output_file, 'w') as file:
                # write result data to the file
                file.write(str(response))

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
            for step in export_data['PB_Sequence'].values():
                if step['Params']:
                    step['Params'] = ['<param_value>' for _ in step['Params']]
        
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


def DisplayTechniqueInfo(technique_id):
    '''Generates Technique information from the MasterRecord.yml and displays it in the offcanvas on the attack page. The offcanvas is triggered by the About Technique button'''
    
    # load MasterRecord.yml file
    master_record = MasterRecord().data
    
    technique_info = master_record.get(technique_id, {})
    
    technique_details = []
    technique_details.append(html.H4(f"Technique: {technique_info.get('Name', 'N/A')}"))
    technique_details.append(html.P(f"ID: {technique_id}"))
    technique_details.append(html.H5(f"Attack Surface:"))
    technique_details.append(html.P(f"{technique_info.get('AttackSurface', 'N/A')}"))
    technique_details.append(html.H5("MITRE ATT&CK Reference:"))
    
    # add mitre technique information
    for mitre_info in technique_info.get('References', {}).get('MITRE', {}).values():
        ul_items = []
        ul_items.append(html.Li(f"Technique: {mitre_info.get('Technique', 'N/A')}"))
        ul_items.append(html.Li(f"Sub-technique: {mitre_info.get('SubTechnique', 'N/A')}"))
        ul_items.append(html.Li(f"Tactic: {', '.join(mitre_info.get('Tactic', ['N/A']))}"))
        mitre_url = mitre_info.get('URL', '#')
        if mitre_url in [None, "#"]:
            ul_items.append(html.Li(dcc.Link("More info", href="#")))
        else:
            ul_items.append(html.Li(dcc.Link("More info", href=mitre_url, target="_blank")))
        technique_details.append(html.Ul(ul_items))
    
    # display additional information under an accordion
    accordion_content = []

    # add technique description
    if technique_info.get('Description', None):
        accordion_content.append(html.H6("Technique Description:",  className="text-muted"))
        accordion_content.append(html.P(technique_info.get('Description', "N/A"), className="text-muted"))

    # add linked additional resources information
    linked_resources = technique_info.get('Resources', [])
    if linked_resources != [None]:
        accordion_content.append(html.H6("Additional Resources:",  className="text-muted"))
        for resource in linked_resources:
            accordion_content.append(html.Li(dcc.Link(f"{resource}", href=resource, target="_blank"), className="text-muted"))

    # add associated notes 
    technique_notes = technique_info.get('Notes','N/A')
    if technique_notes not in [['N/A'],[None]]:
        accordion_content.append(html.H6("Notes:",  className="text-muted"))
        for note in technique_notes:
            accordion_content.append(html.Li(note, className="text-muted"))
    
    # add accordion to modal body
    technique_details.append(
        dbc.Accordion(
            [
                dbc.AccordionItem(accordion_content, title = "Additional Information / Resources"),
            ],
            start_collapsed=True,
        )
    )

    # return technique details
    return technique_details


def TacticMapGenerator():
    '''Function to generate list of available tactics for each attack surface'''
    '''Function to run once at the start of application'''

    # load MasterRecord.yml file
    techniques_info = MasterRecord().data

    Entra_Id_Tactics = []
    Azure_Tactics = []
    AWS_Tactics = []
    M365_Tactics = []

    for t_id in techniques_info:
        if techniques_info[t_id]['References']['MITRE']:
            all_mitre_techniques = techniques_info[t_id]['References']['MITRE']

            for technique in all_mitre_techniques:
                if techniques_info[t_id]['AttackSurface'] == "EntraID":
                    Entra_Id_Tactics += all_mitre_techniques[technique]['Tactic']
                elif techniques_info[t_id]['AttackSurface'] == "Azure":
                    Azure_Tactics += all_mitre_techniques[technique]['Tactic']
                elif techniques_info[t_id]['AttackSurface'] == "AWS":
                    AWS_Tactics += all_mitre_techniques[technique]['Tactic']
                elif techniques_info[t_id]['AttackSurface'] == "M365":
                    M365_Tactics += all_mitre_techniques[technique]['Tactic']
    
    Entra_Id_Tactics = list(set(Entra_Id_Tactics))
    Azure_Tactics = list(set(Azure_Tactics))
    AWS_Tactics = list(set(AWS_Tactics))
    M365_Tactics = list(set(M365_Tactics))

    tactics_map = {"Entra_Id_Tactics" : Entra_Id_Tactics, "Azure_Tactics" : Azure_Tactics, "AWS_Tactics" : AWS_Tactics, "M365_Tactics" : M365_Tactics}

    with open(TACTICS_MAP_FILE, "w") as file:
        yaml.dump(tactics_map, file)
    
    print("[*] Tactic Map Updated")

    return Entra_Id_Tactics, Azure_Tactics, AWS_Tactics, M365_Tactics

def TechniqueMapGenerator():
    '''Function to generate list of available techniques for each attack surface'''
    '''Function to run once at the start of application'''

    # load MasterRecord.yml file
    techniques_info = MasterRecord().data
    
    Entra_Id_Technqiues = []
    Azure_Technqiues = []
    AWS_Technqiues = []
    M365_Technqiues = []

    for t_id in techniques_info:
        if techniques_info[t_id]['AttackSurface'] == "EntraID":
            Entra_Id_Technqiues.append(t_id)
        elif techniques_info[t_id]['AttackSurface'] == "Azure":
            Azure_Technqiues.append(t_id)
        elif techniques_info[t_id]['AttackSurface'] == "AWS":
            AWS_Technqiues.append(t_id)
        elif techniques_info[t_id]['AttackSurface'] == "M365":
            M365_Technqiues.append(t_id)
    
    Entra_Id_Technqiues = list(set(Entra_Id_Technqiues))
    Azure_Technqiues = list(set(Azure_Technqiues))
    AWS_Technqiues = list(set(AWS_Technqiues))
    M365_Technqiues = list(set(M365_Technqiues))

    technique_map = {"Entra_Id_Techniques" : Entra_Id_Technqiues, "Azure_Techniques" : Azure_Technqiues, "AWS_Techniques" : AWS_Technqiues, "M365_Techniques" : M365_Technqiues}

    with open(TECHNIQUES_MAP_FILE, "w") as file:
        yaml.dump(technique_map, file)

    print("[*] Technique Map Updated")
    return Entra_Id_Technqiues, Azure_Technqiues, AWS_Technqiues, M365_Technqiues


def TechniqueOptionsGenerator(tab, tactic):
    '''Function generates list of available techniques as dropdown options dynamically based on the attack surface(tab) and the tactic selected'''
    
    # load MasterRecord.yml file
    techniques_info = MasterRecord().data

    # load techniques map file
    with open(TECHNIQUES_MAP_FILE, "r") as technique_map_data:
        techniques_map = yaml.safe_load(technique_map_data)
    
    if tab == "tab-attack-Azure":
        attack_surface_techniques = techniques_map['Azure_Techniques']
    if tab == "tab-attack-AWS":
        attack_surface_techniques = techniques_map['AWS_Techniques']
    if tab == "tab-attack-M365":
        attack_surface_techniques = techniques_map['M365_Techniques']
    if tab == "tab-attack-EntraID":
        attack_surface_techniques = techniques_map['Entra_Id_Techniques']
        
    technique_options_list = []
    for technique in attack_surface_techniques:
        for mitre_technique in techniques_info[technique]['References']['MITRE']:
            if tactic in techniques_info[technique]['References']['MITRE'][mitre_technique]['Tactic']:
                technique_options_list.append(
                    {
                        "label": html.Div([techniques_info[technique]['Name']], style={"padding-left": "10px","padding-top": "5px", "padding-bottom": "5px", "font-size": 20}, className="bg-dark text-body"),
                        "value": technique,
                    }
                )

    technique_options_element = [
        html.H2(tactic),
        dcc.RadioItems(id = "attack-options-radio", options = technique_options_list, value = technique_options_list[0]["value"], labelStyle={"display": "flex", "align-items": "center"}),
        ]

    return technique_options_element

def TabContentGenerator(tab):

    # load all tactics information for each attack surface from the TacticsMap.yml file
    with open(TACTICS_MAP_FILE, "r") as tactics_file_data:
        tactics_map = yaml.safe_load(tactics_file_data)

    # from tab selected, create tactics dropdown list from the available tactics in the attack surface
    if tab == "tab-attack-M365":
        tactics_options = tactics_map['M365_Tactics']
    if tab == "tab-attack-EntraID":
        tactics_options = tactics_map['Entra_Id_Tactics']
    if tab == "tab-attack-Azure":
        tactics_options = tactics_map['Azure_Tactics']
    if tab == "tab-attack-AWS":
        tactics_options = tactics_map['AWS_Tactics']
    
    # create the dropdown element
    tactic_dropdown_option = []    
    for tactic in tactics_options:
        tactic_dropdown_option.append(
            {
                "label": html.Div([tactic], style={'font-size': 20}, className="text-dark"),
                "value": tactic,
            }
        )    

    tab_content_elements = []

    tab_content_elements.append(dcc.Dropdown(options = tactic_dropdown_option, value = tactic_dropdown_option[0]["value"], id='tactic-dropdown'))
    tab_content_elements.append(html.Br())

    # add element to display technique options under each tactic
    tab_content_elements.append(
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Div(id = "technique-options-div", className= "bg-dark"),
                ], width = 3, md=3, className="bg-dark border-end border-success"),
                dbc.Col([
                    html.Div(id= "attack-config-div",className='bg-dark divBorder d-grid col-6 mx-auto', style={'width' : '100%'}),
                ], width = 7,  className="mb-3"),
            ])  
        ], className="bg-dark p-3 border border-success rounded")
    )
    tab_content_elements.append(html.Br())
    tab_content_elements.append(html.Br())

    tab_content_elements.append(
        dbc.Row([
            dbc.Col(
                html.H4("Response")
            ),
            dbc.Col(
                dbc.Button([
                    DashIconify(icon="mdi:download"),
                ], id="download-technique-response-button", color="primary", style={'float': 'right', 'margin-left': '10px'}),
            )
        ])
    )
    # response loading element
    tab_content_elements.append(
        dcc.Loading(
            id="attack-output-loading",
            type="default",
            children=html.Div(id= "execution-output-div",style={"height":"40vh", "overflowY": "auto", "border":"1px solid #ccc", "padding-right": "10px", "padding-left": "10px", "padding-top": "10px", "padding-bottom": "10px"}, className = "rounded")
        )
    )

    # final tab div to return
    tab_content = html.Div(
        tab_content_elements,
        style={"height":"87vh", "padding-right": "20px", "padding-left": "20px", "padding-top": "20px", "padding-bottom": "20px"}, 
        className="bg-dark"
    )

    return tab_content

def WriteAppLog(action, result = "success"):
    log_file = APP_LOG_FILE
    f = open(log_file,"a")

    fields = ["date_time", "action","result"]
    log_input = {"date_time": str(datetime.today()), "action":action, "result":result}

    write_log = csv.DictWriter(f, fieldnames= fields)
    write_log.writerow(log_input)

    return True
    
def ReadAppLogger():
    log_file = APP_LOG_FILE
    f = open(log_file,"r")
    return csv.DictReader(f)

def ReadTraceLog():
    log_file = TRACE_LOG_FILE
    f = open(log_file,"r")
    return csv.DictReader(f)

def CheckAzureCLIInstall():
    '''Function checks for installation of Azure cli on host'''
    
    if sys.platform.startswith('win'):
        # search in PATH
        az_cli_path = shutil.which("az")
        if az_cli_path:
            return az_cli_path
        
        # if not found in PATH, check in common installation paths on Windows
        common_win_paths = [
            r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin",
            r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin",
        ]
        for path in common_win_paths:
            az_cli_path = os.path.join(path, "az.cmd")
            if os.path.exists(az_cli_path):
                return az_cli_path
            
    else:
        # for non-windows systems, check if 'az' is in PATH
        if shutil.which("az"):
            return "az"
    
    # if az installation not found on host,return None
    return None

def InitializationCheck():
    # Check for local folder
    if Path(APP_LOCAL_DIR).exists():
        pass
    else:
        os.makedirs(APP_LOCAL_DIR)

    # Check for application log file
    if Path(APP_LOG_FILE).exists():
        pass
    else:
        f = open(APP_LOG_FILE,"a")

        fields = ["date_time", "action","result"]
        log_input = {"date_time": "date_time", "action":"action", "result":"result"}

        write_log = csv.DictWriter(f, fieldnames= fields)
        write_log.writerow(log_input)
        print("[*] Application log file created")

    # Check for trace log file
    if Path(TRACE_LOG_FILE).exists():
        pass
    else:
        f = open(TRACE_LOG_FILE,"a")

        fields = ["date_time", "technique", "tactic","attack_surface","result"]
        log_input = {"date_time":"date_time", "technique":"technique", "tactic":"tactic","attack_surface":"attack_surface", "result":"result"}

        write_log = csv.DictWriter(f, fieldnames= fields)
        write_log.writerow(log_input)
        print("[*] Trace log file created")

    # check for msft tokens file
    if Path(MSFT_TOKENS_FILE).exists():
        pass
    else:
        all_tokens_data = {'AllTokens':[]}

        with open(MSFT_TOKENS_FILE, 'w') as file:
            yaml.dump(all_tokens_data, file)

    # check for automator folder
    if Path(AUTOMATOR_DIR).exists():
        # check for automtor/Playbooks folder
        if Path(AUTOMATOR_PLAYBOOKS_DIR).exists():
            pass
        else:
            os.makedirs(AUTOMATOR_PLAYBOOKS_DIR)
            print("[*] Automator dir created")
        
        # check for automator/Outputs folder
        if Path(AUTOMATOR_OUTPUT_DIR).exists():
            pass
        else:
            os.makedirs(AUTOMATOR_OUTPUT_DIR)
            print("[*] Automator outputs dir created")
        
        # check for automator/Exports folder
        if Path(AUTOMATOR_EXPORTS_DIR).exists():
            pass
        else:
            os.makedirs(AUTOMATOR_EXPORTS_DIR)
            print("[*] Automator exports dir created")

        # check for automator/Schedules.yml file
        if Path(AUTOMATOR_SCHEDULES_FILE).exists():
            pass
        else:
            # create Schedules.yml config file
            with open(AUTOMATOR_SCHEDULES_FILE, 'w') as file:
                pass
            print("[*] Schedules config file created")
            
    else:
        # create all automator dirs and files
        os.makedirs(AUTOMATOR_DIR)
        os.makedirs(AUTOMATOR_PLAYBOOKS_DIR)
        os.makedirs(AUTOMATOR_OUTPUT_DIR)
        with open(AUTOMATOR_SCHEDULES_FILE, 'w') as file:
            pass
        print("[*] Automator files created")

    # check az cli installation
    if CheckAzureCLIInstall():
        pass
    else:
        # print warning on terminal
        warning = '''
        ⚠️  WARNING: Azure CLI (az) not found! ⚠️
        --------------------------------------------
        The Azure CLI is required to run the Azure modules but was not found on the system.
        Please ensure that:
        1. Azure CLI is installed on the system.
        2. The installation directory is added to your system's PATH.
        3. You have restarted your terminal or IDE after installation.

        For installation instructions, visit:
        https://learn.microsoft.com/en-us/cli/azure/install-azure-cli

        After installation, you may need to restart your terminal or add the Azure CLI 
        installation directory to your PATH manually.
        '''
        print(warning)


def PlaybookCreateCSVReport(report_file_name, time_stamp, module, result):
    '''Function to create and write to execution summary report in CSV format'''

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

def AddNewSchedule(schedule_name, playbook_id, start_date, end_date, execution_time, repeat, repeat_frequency):
    # automator file
    with open(AUTOMATOR_SCHEDULES_FILE, "r") as schedule_data:
        schedules = yaml.safe_load(schedule_data)

    # if no schedule present, initialize dictionary
    if schedules == None:
        schedules = {}

    # input handling
    if schedule_name in [None, ""]:
        sched_create_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        schedule_name = f"schedule-{sched_create_time}"

    schedules[schedule_name] = {"Playbook_Id" : playbook_id, "Start_Date" : start_date, "End_Date" : end_date, "Execution_Time" : execution_time, "Repeat" : str(repeat), "Repeat_Frequency" : repeat_frequency}
    # update schedules file
    with open(AUTOMATOR_SCHEDULES_FILE, "w") as file:
        yaml.dump(schedules, file)


def GetAllPlaybooks():
    # list all playbooks
    all_playbooks = []
    try:
        # check playbooks directory
        dir_contents = os.listdir(AUTOMATOR_PLAYBOOKS_DIR)
        for content in dir_contents:
            if os.path.isfile(os.path.join(AUTOMATOR_PLAYBOOKS_DIR, content)) and content.lower().endswith(".yml"):
                # if content is a yml file
                all_playbooks.append(content)

        return all_playbooks
    
    except FileNotFoundError:
        return "File not found"
    except PermissionError:
        return "Permissions error"
    except:
        return "Error"

def DisplayPlaybookInfo(selected_pb):
    for pb in GetAllPlaybooks():
        playbook = Playbook(pb)
        if  playbook.name == selected_pb:
            break
    display_elements = []

    # display playbook name
    display_elements.append(html.H4(f"Name : {playbook.name}"))
    display_elements.append(html.Br())

    # display playbook description
    display_elements.append(html.H5("Description : "))
    display_elements.append(html.P(playbook.description))

    # display playbook step count
    display_elements.append(html.H5(f"Steps Count : {playbook.steps}"))
    display_elements.append(html.P(""))

    # display playbook author
    display_elements.append(html.H5("Plabook Author : "))
    display_elements.append(html.P(playbook.author))

    # display playbook creation date
    display_elements.append(html.H5("Plabook Creation Date : "))
    display_elements.append(html.P(playbook.creation_date))

    # display playbook references
    display_elements.append(html.H5("Plabook References : "))
    if playbook.references: 
        if type(playbook.references) == list:
            for ref in playbook.references:
                display_elements.append(html.Li(dcc.Link(ref, href=ref, target='_blank')))
        else:
            display_elements.append(html.Li(dcc.Link(playbook.references, href=playbook.references, target='_blank')))
    else:
        display_elements.append(html.P("N/A"))

    return display_elements 