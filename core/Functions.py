import yaml
import csv
import os
import sys
import shutil
import json
from typing import Union, Any, Optional
import datetime
from pathlib import Path
from dash import html, dcc, Patch
import dash_daq as daq
import dash_cytoscape as cyto
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify
from core.Constants import *
from core.playbook.playbook import Playbook
from core.entra.entra_token_manager import EntraTokenManager
from core.aws.aws_session_manager import SessionManager
from core.azure.azure_access import AzureAccess
from attack_techniques.technique_registry import TechniqueRegistry

def generate_technique_info(technique_id)-> list:
    """
    Generates list of elements containing technique information that can be displayed inside any other html element. 
    """
    def create_mitre_info_cards(mitre_techniques):
        """Create dbc.cards with technique MITRE info"""
        mitre_cards = []
        for mitre_info in mitre_techniques:
            mitre_card = dbc.Card([
                dbc.CardBody([
                    html.P(f"Technique: {mitre_info.technique_name}", className="card-text"),
                    html.P(f"Sub-technique: {mitre_info.sub_technique_name}", className="card-text"),
                    html.P(f"Tactic: {', '.join(mitre_info.tactics)}", className="card-text"),
                    dcc.Link("Visit MITRE", href=mitre_info.mitre_url if mitre_info.mitre_url not in [None, "#"] else "#", target="_blank", className="card-link")
                ])
            ], className="mb-2")
            mitre_cards.append(mitre_card)
        return html.Div(mitre_cards)
    
    def create_azure_trm_info_cards(azure_trm_techniques):
        """Create dbc.cards with technique Azure Threat Research Matrix info"""
        mitre_cards = []
        for azure_trm_info in azure_trm_techniques:
            mitre_card = dbc.Card([
                dbc.CardBody([
                    html.P(f"Technique: {azure_trm_info.technique_name}", className="card-text"),
                    html.P(f"Sub-technique: {azure_trm_info.sub_technique_name}", className="card-text"),
                    html.P(f"Tactic: {', '.join(azure_trm_info.tactics)}", className="card-text"),
                    dcc.Link("Visit Azure Threat Research Matrix", href=azure_trm_info.azure_trm_url if azure_trm_info.azure_trm_url not in [None, "#"] else "#", target="_blank", className="card-link")
                ])
            ], className="mb-2")
            mitre_cards.append(mitre_card)
        return html.Div(mitre_cards)
    
    # Get technique information from technique registry
    technique = TechniqueRegistry.get_technique(technique_id)()
    technique_category = TechniqueRegistry.get_technique_category(technique_id)
    
    # Main technique information card
    main_info_card = dbc.Card([
        dbc.CardHeader(html.H4(f"Technique: {technique.name}", className="mb-0")),
        
        dbc.CardBody([
            html.H5(f"Attack Surface: {technique_category}", className="mb-3"),
            html.H5("Technique Description:", className="mb-2"),
            html.P(technique.description, className="mb-3"),
            html.H5("MITRE ATT&CK Reference:", className="mb-2"),
            create_mitre_info_cards(technique.mitre_techniques)
        ])
    ], className="mb-3")

    modal_content = [main_info_card]
    
    # Display Azure threat research matrix info - only for Azure techniques
    if technique_category == "azure":
        if technique.azure_trm_techniques:
            modal_content.append(
                dbc.Accordion([
                    dbc.AccordionItem(create_azure_trm_info_cards(technique.azure_trm_techniques), title="Azure Threat Research Matrix Reference")
                ], start_collapsed=True, className="mb-3")
            )
    # Technique references
    if technique.references:
        modal_content.append(
            dbc.Accordion([
                dbc.AccordionItem(
                    [dcc.Link("Visit Ref", href=ref if ref not in [None, "#"] else "#", target="_blank", className="card-link") for ref in technique.references],
                    title="Technique References"
                )
            ], start_collapsed=True, className="mb-3")
        )  
    
    # Technique notes
    if technique.notes:
        modal_content.append(
            dbc.Accordion([
                dbc.AccordionItem(technique.notes, title="Technique Notes")
            ], start_collapsed=True, className="mb-3")
        )

    # Return final modal body content
    return modal_content

def WriteAppLog(action, result = "success"):
    log_file = APP_LOG_FILE
    f = open(log_file,"a")

    fields = ["date_time", "action","result"]
    log_input = {"date_time": str(datetime.datetime.today()), "action":action, "result":result}

    write_log = csv.DictWriter(f, fieldnames= fields)
    write_log.writerow(log_input)

    return True

def check_azure_cli_install():
    """
    Function checks for installation of Azure cli on host
    """
    
    if sys.platform.startswith('win'):
        # Search in PATH
        az_cli_path = shutil.which("az")
        if az_cli_path:
            return az_cli_path
        
        # If not found in PATH, check in common installation paths on Windows
        common_win_paths = [
            r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin",
            r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin",
        ]
        for path in common_win_paths:
            az_cli_path = os.path.join(path, "az.cmd")
            if os.path.exists(az_cli_path):
                return az_cli_path
            
    else:
        # For non-windows systems, check if 'az' is in PATH
        if shutil.which("az"):
            return "az"
    
    # If az installation not found on host,return None
    return None

def run_initialization_check():
    """
    Checks for app directories and creates missing directories on app initialization
    """
    # Check for local folder
    if Path(APP_LOCAL_DIR).exists():
        pass
    else:
        os.makedirs(APP_LOCAL_DIR)

    # Check for output folder
    if Path(OUTPUT_DIR).exists():
        pass
    else:
        os.makedirs(OUTPUT_DIR)
    
    # Check for report folder
    if Path(REPORT_DIR).exists():
        pass
    else:
        os.makedirs(REPORT_DIR)

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

    # Check for msft tokens file
    if Path(MSFT_TOKENS_FILE).exists():
        pass
    else:
        all_tokens_data = {'AllTokens':[]}

        with open(MSFT_TOKENS_FILE, 'w') as file:
            yaml.dump(all_tokens_data, file)

    # Check for automator folder
    if Path(AUTOMATOR_DIR).exists():
        # Check for automtor/Playbooks folder
        if Path(AUTOMATOR_PLAYBOOKS_DIR).exists():
            pass
        else:
            os.makedirs(AUTOMATOR_PLAYBOOKS_DIR)
            print("[*] Automator dir created")
        
        # Check for automator/Outputs folder
        if Path(AUTOMATOR_OUTPUT_DIR).exists():
            pass
        else:
            os.makedirs(AUTOMATOR_OUTPUT_DIR)
            print("[*] Automator outputs dir created")
        
        # Check for automator/Exports folder
        if Path(AUTOMATOR_EXPORTS_DIR).exists():
            pass
        else:
            os.makedirs(AUTOMATOR_EXPORTS_DIR)
            print("[*] Automator exports dir created")

        # Check for automator/Schedules.yml file
        if Path(AUTOMATOR_SCHEDULES_FILE).exists():
            pass
        else:
            # Create Schedules.yml config file
            with open(AUTOMATOR_SCHEDULES_FILE, 'w') as file:
                pass
            print("[*] Schedules config file created")
            
    else:
        # Create all automator dirs and files
        os.makedirs(AUTOMATOR_DIR)
        os.makedirs(AUTOMATOR_PLAYBOOKS_DIR)
        os.makedirs(AUTOMATOR_OUTPUT_DIR)
        with open(AUTOMATOR_SCHEDULES_FILE, 'w') as file:
            pass
        print("[*] Automator files created")

    # Check az cli installation
    if check_azure_cli_install():
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

    # Check for logging config file
    if not os.path.exists(LOGGING_CONFIG_FILE):
        with open(LOGGING_CONFIG_FILE, 'w') as config_file:
            yaml.dump({
                'logger_level': 'DEBUG',
                'console_handler': {
                    'enabled': False,
                    'level': 'INFO',
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                },
                'file_handler': {
                    'enabled': True,
                    'level': 'DEBUG',
                    'filename': 'app.log',
                    'max_bytes': 5242880,  # 5 MB
                    'backup_count': 3,
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                }
            }, config_file)
        print("[*] Logging config file created")

def AddNewSchedule(schedule_name, playbook_id, start_date, end_date, execution_time, repeat, repeat_frequency):
    # automator file
    with open(AUTOMATOR_SCHEDULES_FILE, "r") as schedule_data:
        schedules = yaml.safe_load(schedule_data)

    # if no schedule present, initialize dictionary
    if schedules == None:
        schedules = {}

    # input handling
    if schedule_name in [None, ""]:
        sched_create_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
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

def generate_playbook_info(selected_pb):
    """
    Generates a display element with dbc.Cards containing playbook details that can be displayed in HTML elements like div, modal, etc. 

    :param selected_pb: Name of a playbook (from playbook config)
    """
    for pb in GetAllPlaybooks():
        playbook = Playbook(pb)
        if  playbook.name == selected_pb:
            break
    display_elements = []

    def create_sequence_card(sequence):
        if not sequence:
            return dbc.Card(
                [
                    dbc.CardHeader(html.H5("PB_Sequence", className="mb-0")),
                    dbc.CardBody(html.P("No steps defined", className="card-text"))
                ],
                className="mb-3"
            )
        
        steps = []
        for step_num, step_data in sequence.items():
            params = step_data.get('Params', {})
            param_cards = []
            if params:
                for key, value in params.items():
                    param_cards.append(
                        dbc.Card([
                            dbc.CardBody([
                                html.H6(key, className="card-subtitle mb-2 text-muted"),
                                html.P(str(value), className="card-text")
                            ])
                        ], className="mb-2")
                    )
            else:
                param_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.P("No parameters", className="card-text text-muted")
                        ])
                    ], className="mb-2")
                )

            param_accordion = dbc.Accordion([
                dbc.AccordionItem(
                    param_cards,
                    title="Parameters",
                )
            ], start_collapsed=True)

            step_content = [
                html.H6(f"Step {step_num}", className="mb-2"),
                html.P(f"Module: {step_data.get('Module', 'N/A')}", className="mb-1"),
                html.P(f"Wait: {step_data.get('Wait', 'N/A')}", className="mb-2"),
                param_accordion
            ]
            steps.append(dbc.Card(dbc.CardBody(step_content), className="mb-3"))
        
        return dbc.Card(
            [
                dbc.CardHeader(html.H5("PB_Sequence", className="mb-0")),
                dbc.CardBody(steps)
            ],
            className="mb-3"
        )
    
    def create_references_card(references):
        """
        Creates dbc.card element with information in PB_References
        """
        if not references:
            return dbc.Card(
                [
                    dbc.CardHeader(html.H5("PB_References", className="mb-0")),
                    dbc.CardBody(html.P("No references available", className="card-text"))
                ],
                className="mb-3"
            )
        
        reference_links = [
            html.Li(
                html.A(ref, href=ref, target="_blank", rel="noopener noreferrer"),
                className="mb-2"
            ) for ref in references
        ]
        
        return dbc.Card(
            [
                dbc.CardHeader(html.H5("PB_References", className="mb-0")),
                dbc.CardBody([
                    html.P("Click on the links below to open in a new tab:", className="mb-2"),
                    html.Ul(reference_links, className="pl-3")
                ])
            ],
            className="mb-3"
        )
    
    def create_field_card(key, value):
        """
        Creates dbc.card with all information in Playbook configuration
        """
        if key == 'PB_Sequence':
            return create_sequence_card(value)
        elif key == 'PB_References':
            return create_references_card(value)
        return dbc.Card(
            [
                dbc.CardHeader(html.H5(key, className="mb-0")),
                dbc.CardBody(
                    html.P(json.dumps(value, indent=2) if isinstance(value, (dict, list)) else str(value), 
                        className="card-text", style={"white-space": "pre-wrap"})
                )
            ],
            className="mb-3"
        )

    display_elements = [create_field_card(key, value) for key, value in playbook.data.items()]

    return display_elements

def ParseTechniqueResponse(technique_response):
    """
    Function to parse the technique execution response and display it structured

    :param technique_response: Raw output from a Halberd technique execution
    """
    # Check if technique output is in the expected tuple format (success, raw_response, pretty_response)
    if isinstance(technique_response, tuple) and len(technique_response) == 3:
        success, raw_response, pretty_response = technique_response
        # Parse output
        if pretty_response != None:
            response = pretty_response
        else:
            response = raw_response
    else:
        response = technique_response

    # Initialize the response div elements list
    response_div_elements = []

    # Display notification based on technique result
    try:
        if success == True:
            response_div_elements.append(
                dbc.Toast(
                    children = "Success",
                    id="output-notification",
                    header="Technique Result",
                    is_open=True,
                    dismissable=True,
                    duration=5000,
                    color="success",
                    style={"position": "fixed", "top": 166, "right": 10, "width": 350},
                )
            )
        else:
            response_div_elements.append(
                dbc.Toast(
                    children = "Failed",
                    id="output-notification",
                    header="Technique Result",
                    is_open=True,
                    dismissable=True,
                    duration=5000,
                    color="danger",
                    style={"position": "fixed", "top": 168, "right": 10, "width": 350},
                )
            )
    except:
        pass
    
    # Format parsed response based on response data type (dict / list / str)
    def parse_data(data: str) -> Union[dict, list, str]:
        """
        Parse the input data string

        Args:
            data (str): The input data string.

        Returns:
            Union[dict, list, str]: Parsed data or "empty" for empty inputs.
        """
        try:
            if isinstance(data, str):
                parsed = json.loads(data)
                return parsed if parsed else "empty"
            return data
        except json.JSONDecodeError:
            return data

    def is_empty(data: Any) -> bool:
        """
        Check if the input data is empty.

        Args:
            data (Any): The input data to check.

        Returns:
            bool: True if the data is empty, False otherwise.
        """
        if data == "empty":
            return True
        if isinstance(data, (str, list, dict)) and not data:
            return True
        return False

    def format_output(data: Any, level: int = 0) -> Union[dbc.Card, dbc.ListGroup, html.Span]:
        """
        Format the input data into Dash component(dbc.card).

        Args:
            data (Any): The input data to format.
            level (int): The current nesting level (default: 0).

        Returns:
            Union[dbc.Card, dbc.ListGroup, html.Span]: Formatted Dash components.
        """
        if is_empty(data):
            return html.Em("Empty")
        if isinstance(data, dict):
            return dbc.Card([
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col(html.Strong(key), width=3),
                        dbc.Col(format_output(value, level + 1), width=9)
                    ], className="mb-2") for key, value in data.items()
                ])
            ], className="mb-3")
        if isinstance(data, list):
            return dbc.ListGroup([
                dbc.ListGroupItem(format_output(item, level + 1)) for item in data
            ], flush=True)
        return html.Span(str(data))

    def create_cards(data: Any) -> Union[dbc.Card, list]:
        """
        Create cards for the top-level data structure.

        Args:
            data (Any): The input data to create cards for.

        Returns:
            Union[dbc.Card, list]: A single card or list of cards.
        """
        if is_empty(data):
            return dbc.Card(dbc.CardBody([
                html.H5("Result", className="card-title"),
                html.P("No results found", className="card-text text-muted")
            ]), className="mb-3")
        if isinstance(data, list):
            return [
                dbc.Card(dbc.CardBody(format_output(item)), className="mb-3")
                for item in data
            ]
        if isinstance(data, dict):
            return [
                dbc.Card(dbc.CardBody([
                    html.H5(key, className="card-title"),
                    format_output(value)
                ]), className="mb-3")
                for key, value in data.items()
            ]
        return dbc.Card(dbc.CardBody(format_output(data)), className="mb-3")

    parsed_response = parse_data(response)
    return create_cards(parsed_response)

def playbook_viz_generator(playbook_name: Optional[str]) -> cyto.Cytoscape:
    """
    Generate a visualization of a playbook's attack sequence.

    This function creates a Cytoscape graph representation of a playbook's
    attack sequence. If no playbook is selected, it returns a div with a
    "No Selection" message.

    Args:
        playbook_name (Optional[str]): The name of the playbook to visualize.
            If None, a "No Selection" message is displayed.

    Returns:
        cyto.Cytoscape: A cytoscope component containing graph of the playbook's attack sequence or a html.Div with "No Selection" message.

    Notes:
        - The function assumes the existence of several global objects and
          functions: get_all_playbooks(), Playbook, and TechniqueRegistry.
        - Each step in the playbook sequence is represented by two nodes:
          one for the technique and one for the wait time.
    """
    if playbook_name is None:
        return html.Div([
            html.H3('No Selection'),
            ], style={'textAlign': 'center', 'padding-top': '50px'})
    
    else:
        for pb in GetAllPlaybooks():
            pb_config = Playbook(pb)
            if pb_config.name == playbook_name:
                break
        
        # Initialize array for cytoscope
        attack_sequence_viz_elements = []
        n = 0
        position_x = 50

        for step_no,step in pb_config.data['PB_Sequence'].items():
            step_module_id = step['Module']
            step_wait = step['Wait']
            attack_sequence_viz_elements.append({'data': {'id': str(n), 'label': f"{TechniqueRegistry.get_technique(step_module_id)().name}", 'info':{step_no: step}}, 'position': {'x': position_x, 'y': 50}})
            position_x += 70
            n += 1

            attack_sequence_viz_elements.append({'data': {'id': str(n), 'label': str(step_wait), 'info':"time"}, 'position': {'x': position_x, 'y': 50}, 'classes': 'timenode'})
            position_x += 70
            n += 1
        
        while n>1:
            n = n-1
            attack_sequence_viz_elements.append({'data': {'source': str(n-1), 'target': str(n)}})
        
        return cyto.Cytoscape(
                id='auto-attack-sequence-cytoscape-nodes',
                layout={'name': 'preset'},
                style={'height': '20vh'},
                elements= attack_sequence_viz_elements,
                stylesheet=[
                    # Add styles for the graph here
                    {
                        'selector': 'node',
                        'style': {
                            'label': 'data(label)',
                            'background-color': '#FFFFFF',
                            'color': '#000000',
                            'width': '40px',
                            'height': '40px',
                            'text-halign': 'center',
                            'text-valign': 'center',
                            'text-wrap': 'wrap',
                            'text-max-width': '50',
                            'font-size': '5px',
                            'shape': 'square'
                        }
                    },
                    {
                        'selector': 'edge',
                        'style': {
                            'curve-style': 'bezier',
                            'target-arrow-shape': 'triangle',
                            'line-color': '#000000',
                            'target-arrow-color': '#000000',
                        }
                    },
                    {
                        'selector': '.timenode',
                        'style': {
                            'label': 'data(label)',
                            'background-color': '#000000',
                            'color': '#fff',
                            'text-halign': 'center',
                            'text-valign': 'center',
                            'text-wrap': 'wrap',
                            'text-max-width': '20px',
                            'shape': 'ellipse',
                            'opacity': 0.7,
                            'width': '20px',
                            'height': '20px',
                        }
                    }
                ]
                )

def generate_attack_tactics_options(tab):
    """
    Function dynamically generates tatics options in the Tactics Dropdown element on Attack page. 
    Fetches the available tactics in a given attack surface.

    :param tab: attack surface name from the tab selected on Attack page
    """

    # Load all technique information from registry
    technique_registry = TechniqueRegistry()

    # From tab selected, create tactics dropdown list from the available tactics in the selected attack surface
    if tab == "tab-attack-M365":
        tactics_options = technique_registry.list_tactics("m365")
    if tab == "tab-attack-EntraID":
        tactics_options = technique_registry.list_tactics("entra_id")
    if tab == "tab-attack-Azure":
        tactics_options = technique_registry.list_tactics("azure")
    if tab == "tab-attack-AWS":
        tactics_options = technique_registry.list_tactics("aws")
    
    # Create the dropdown element
    tactic_dropdown_option = []    
    for tactic in tactics_options:
        tactic_dropdown_option.append(
            {
                "label": html.Div([tactic], style={'font-size': 20}, className="text-dark"),
                "value": tactic,
            }
        )

    return tactic_dropdown_option

def generate_attack_technique_options(tab, tactic):
    """
    Function dynamically generates technique radio options on attack page. 
    Fetches the available techniques in a given attack surface and tactic.

    :param tab: attack surface name from the tab selected on Attack page
    :param tactic: Mitre tactic name from the option selected in Tactics Dropdown
    """
    # Load all technique information from registry
    technique_registry = TechniqueRegistry()
    attack_surface_techniques ={}
    
    if tab == "tab-attack-Azure":
        attack_surface_techniques = technique_registry.list_techniques("azure")
    elif tab == "tab-attack-AWS":
        attack_surface_techniques = technique_registry.list_techniques("aws")
    elif tab == "tab-attack-M365":
        attack_surface_techniques = technique_registry.list_techniques("m365")
    elif tab == "tab-attack-EntraID":
        attack_surface_techniques = technique_registry.list_techniques("entra_id")
        
    technique_options_list = []
    # tracker list to avoid duplicate entry
    technique_tracker = []
    for technique_module, technique in attack_surface_techniques.items():
        for mitre_technique in technique().get_mitre_info():
            if tactic in mitre_technique['tactics']:
                if technique_module not in technique_tracker:
                    technique_tracker.append(technique_module)
                    technique_options_list.append(
                        {
                            "label": html.Div([technique().name], style={"padding-left": "10px","padding-top": "5px", "padding-bottom": "5px", "font-size": 20}, className="bg-dark text-body"),
                            "value": technique_module,
                        }
                    )

    technique_options_element = [
        dcc.RadioItems(id = "attack-options-radio", options = technique_options_list, value = technique_options_list[0]["value"], labelStyle={"display": "flex", "align-items": "center"})
    ]
    
    return technique_options_element

def generate_attack_technique_config(technique):
    """
    Function generates the technique configuration view in attack page. 
    Converts technique inputs into UI input fields. Also, adds 'Technique Execute' and 'Add to Playbook' buttons. 

    :param technique: Exact name of technique in Halberd technique registry
    """
    technique_config = TechniqueRegistry.get_technique(technique)().get_parameters()

    config_div_display = Patch()
    config_div_display.clear()

    # Check if technique requires input
    if len(technique_config.keys()) > 0:
        config_div_elements = []

        for input_field, input_config in technique_config.items():
            # Indicate required fields with * on GUI
            if input_config['required']:
                config_div_elements.append(dbc.Label(input_config['name']+" *"))
            else:
                config_div_elements.append(dbc.Label(input_config['name']))

            if input_config['input_field_type'] in ["text", "email", "password", "number"]:
                config_div_elements.append(dbc.Input(
                    type = input_config['input_field_type'],
                    # Display default values in placeholder for technique param
                    placeholder = input_config['default'] if input_config['default'] else "",
                    debounce = True,
                    id = {"type": "technique-config-display", "index": input_field},
                    className="bg-dark border text-light",
                ))
            elif input_config['input_field_type'] == "bool":
                config_div_elements.append(daq.BooleanSwitch(
                    id = {"type": "technique-config-display-boolean-switch", "index": input_field}, 
                    on=input_config['default'])
                )
            elif input_config['input_field_type'] == "upload":
                config_div_elements.append(dcc.Upload(
                    id = {"type": "technique-config-display-file-upload", "index": input_field}, 
                    children=html.Div([html.A('Select a file or Drag one here')]), 
                    className="bg-dark",
                    style={'width': '50%', 'height': '60px', 'lineHeight': '60px', 'borderWidth': '1px', 'borderStyle': 'dashed', 'borderRadius': '5px', 'textAlign': 'center', 'margin': '10px'})
                )
                
            config_div_elements.append(html.Br())

        config_div = html.Div(config_div_elements, className='d-grid col-6 mx-auto', style={'width' : '100%'})
        config_div_display.append(config_div)
    else:
        config_div_display.append(
            html.Div(html.B("No config required! Hit 'Execute'"), className='d-grid col-6 mx-auto', style={'width' : '100%'})
        )

    config_div_display.append(html.Br())

    # Add technique execute button
    config_div_display.append(
        (html.Div([
            dbc.Button("Execute Technique", id="technique-execute-button", n_clicks=0, color="danger"),
            html.Br(),
        ], className="d-grid col-3 mx-auto"))
    )

    # Add add to playbook button
    config_div_display.append(
        html.Div([
            dbc.Button("+ Add to Playbook", id="open-add-to-playbook-modal-button", n_clicks=0, color="secondary")
        ], style={'display': 'flex', 'justify-content': 'center', 'gap': '10px'})
    )
    
    # Create plabook modal dropdown content
    playbook_dropdown_options = []    
    for pb in GetAllPlaybooks():
        playbook_dropdown_options.append(
            {
                "label": html.Div([Playbook(pb).name], style={'font-size': 20}, className="text-dark"),
                "value": Playbook(pb).name,
            }
        )

    # Add add to playbook modal
    config_div_display.append(
        dbc.Modal(
            [
                dbc.ModalHeader("Add Technique to Playbook"),
                dbc.ModalBody([
                    dbc.Label("Select Playbook to Add Step"),
                    dcc.Dropdown(
                        options = playbook_dropdown_options, 
                        value = None, 
                        id='att-pb-selector-dropdown',
                        placeholder="Select Playbook",
                        ),
                    html.Br(),
                    dbc.Label("Add to Step # (Optional)", className="text-light"),
                    dbc.Input(id='pb-add-step-number-input', placeholder="3", type= "number", className="bg-dark text-light"),
                    html.Br(),
                    dbc.Label("Wait in Seconds After Step Execution (Optional)", className="text-light"),
                    dbc.Input(id='pb-add-step-wait-input', placeholder="120", type= "number", className="bg-dark text-light")
                ]),
                dbc.ModalFooter([
                    dbc.Button("Cancel", id="close-add-to-playbook-modal-button", className="ml-auto", color="danger", n_clicks=0),
                    dbc.Button("Add to Playbook", id="confirm-add-to-playbook-modal-button", className="ml-2", color="danger", n_clicks=0)
                ])
            ],
            id="add-to-playbook-modal",
            is_open=False,
        )
    )
    return config_div_display

def generate_entra_access_info(access_token):
    def create_scope_badges(scopes):
        return [dbc.Badge(scope, color="dark", className="me-1 mb-1 small") for scope in scopes]

    def get_entity_type_icon(entity_type):
        if entity_type.lower() == "user":
            return "mdi:account"
        elif entity_type.lower() == "app":
            return "mdi:application"
        else:
            return "mdi:help-circle"  # Default icon for unknown types
        
    if not access_token:
        return dbc.Card(
            dbc.CardBody([
                html.H4("Access Token Status", className="card-title"),
                html.P("No Active Access Token", className="text-danger")
            ]),
            className="mb-3 text-white"
        )
    
    # Halberd entra token manager
    manager = EntraTokenManager()

    # Fetch currently active token if token value is "active"
    if access_token == "active":
        access_token = manager.get_active_token()
    
    # Decode token using Halberd EntraTokenManager
    try:
        access_info = manager.decode_jwt_token(access_token)
    except Exception as e:
        return dbc.Card(
            dbc.CardBody([
                html.H4("Access Token Status", className="card-title"),
                html.P("Failed to decode access token", className="text-danger")
            ]),
            className="mb-3 text-white"
        )
    
    # Handle corrupt tokens
    if access_info is None:
        return dbc.Card(
            dbc.CardBody([
                html.H4("Access Token Status", className="card-title"),
                html.P("Failed to decode access token", className="text-danger")
            ]),
            className="mb-3 text-white"
        )
    
    # Parse token and create ui elements
    entity_type = access_info.get('Entity Type', '').lower()
    entity_type_icon = get_entity_type_icon(entity_type)

    card_content = [
        dbc.Row([
            dbc.Col([
                html.Div([
                    DashIconify(icon="mdi:identifier", className="me-2"),  # Icon for entity
                    html.Strong("Entity:"),
                    html.Span(access_info.get('Entity', ''), className="ms-2 text-info")
                ], className="mb-2"),
                html.Div([
                    DashIconify(icon=entity_type_icon, className="me-2"),  # Dynamic icon based on entity type
                    html.Strong("Entity Type:"),
                    html.Span(access_info.get('Entity Type', ''), className="ms-2")
                ], className="mb-2"),
                html.Div([
                    DashIconify(icon="mdi:key-variant", className="me-2"), # Key icon
                    html.Strong("Access Type:"),
                    html.Span(access_info.get('Access Type', ''), className="ms-2")
                ], className="mb-2"),
            ], width=6),
            dbc.Col([
                html.Div([
                    DashIconify(icon="mdi:clock-outline", className="me-2"), # Clock icon for token expiration time
                    html.Strong("Access Exp:"),
                    html.Span(f"{access_info.get('Access Exp', '')} UTC", className="ms-2"),
                    html.Span("Expired", className="ms-2 text-danger") if access_info.get('Access Exp', '') < datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') else html.Span("Valid", className="ms-2 text-success")
                ], className="mb-2"),
                html.Div([
                    DashIconify(icon="mdi:domain", className="me-2"),  # Icon for tenant identifier
                    html.Strong("Target Tenant:"),
                    html.Span(access_info.get('Target Tenant', ''), className="ms-2")
                ], className="mb-2"),
                html.Div([
                    DashIconify(icon="mdi:settings-applications", className="me-2"),  # Icon for tenant identifier
                    html.Strong("Target App:"),
                    html.Span(access_info.get('Target App Name', ''), className="ms-2")
                ], className="mb-2"),
            ], width=6)
        ]),
        dbc.Row([
            dbc.Col([
                html.Div([
                    DashIconify(icon="mdi:shield-check", className="me-2"), # Shield icon for access scope
                    html.Strong("Access scope:")
                ], className="mb-2"),
                html.Div(create_scope_badges(access_info.get('Access scope', '')), className="d-flex flex-wrap")
            ], width=12)
        ], className="mt-3")
    ]
    
    return dbc.Card(
        dbc.CardBody([
            html.H4([DashIconify(icon="mdi:key-chain", className="me-2"), "Access Token Information"], className="card-title mb-3"),
            *card_content
        ]),
        className="mb-3 text-white"
    )

def generate_aws_access_info(session_name):
    info_output_div = []

    if session_name:
        info_output_div.append(html.Br())
        info_output_div.append(html.H5("Access : "))

        manager = SessionManager()
        # set default session
        manager.set_active_session(session_name)
        my_session = manager.get_session(session_name)
        sts_client = my_session.client('sts')

        try:
            session_info = sts_client.get_caller_identity()
            
            card_content = [
                dbc.Row([
                    dbc.Col([
                        html.Div([
                            DashIconify(icon="mdi:account-key", className="me-2"),
                            html.Strong("User ID:"),
                            html.Span(session_info['UserId'], className="ms-2 text-info")
                        ], className="mb-3"),
                        html.Div([
                            DashIconify(icon="mdi:account-cash", className="me-2"),
                            html.Strong("Account:"),
                            html.Span(session_info['Account'], className="ms-2")
                        ], className="mb-3"),
                        html.Div([
                            DashIconify(icon="mdi:identifier", className="me-2"),
                            html.Strong("ARN:"),
                            html.Span(session_info['Arn'], className="ms-2")
                        ], className="mb-3"),
                    ], width=12)
                ])
            ]
            
            info_output_div.append(
                dbc.Card(
                    dbc.CardBody([
                        html.H4([
                            DashIconify(icon="mdi:aws", className="me-2"),
                            "Access: ",
                            html.Span("VALID SESSION", className="text-success")
                        ], className="card-title mb-3"),
                        *card_content
                    ]),
                    className="mb-3 text-white"
                )
            )
        except:
            info_output_div.append(
                dbc.Card(
                    dbc.CardBody([
                        html.H4([
                            DashIconify(icon="mdi:aws", className="me-2"),
                            "Access: ",
                            html.Span("NO VALID SESSION", className="text-danger")
                        ], className="card-title")
                    ]),
                    className="mb-3 text-white"
                )
            )
    else:
        info_output_div.append(
            dbc.Card(
                dbc.CardBody([
                    html.H4([
                        DashIconify(icon="mdi:aws", className="me-2"),
                        "Access: ",
                        html.Span("NO VALID SESSION", className="text-danger")
                    ], className="card-title")
                ]),
                className="mb-3 text-white"
            )
        )

    return info_output_div

def generate_azure_access_info(subscription):
    info_output_div = []

    if subscription is None:
        # If no subscription is selected, proceed with default subscription
        pass
    else:
        selected_subscription = subscription
        AzureAccess().set_active_subscription(selected_subscription)

    # Get set subscription info
    current_access = AzureAccess().get_current_subscription_info()

    try:
        if current_access is not None:
            # Construct session info to display
            card_content = [
                dbc.Row([
                    dbc.Col([
                        html.Div([
                            DashIconify(icon="mdi:cloud", className="me-2"),
                            html.Strong("Environment Name:"),
                            html.Span(current_access.get("environmentName", "N/A"), className="ms-2 text-info")
                        ], className="mb-2"),
                        html.Div([
                            DashIconify(icon="mdi:tag", className="me-2"),
                            html.Strong("Name:"),
                            html.Span(current_access.get("name", "N/A"), className="ms-2")
                        ], className="mb-2"),
                        html.Div([
                            DashIconify(icon="mdi:identifier", className="me-2"),
                            html.Strong("Subscription ID:"),
                            html.Span(current_access.get("id", "N/A"), className="ms-2")
                        ], className="mb-2"),
                        html.Div([
                            DashIconify(icon="mdi:flag-variant", className="me-2"),
                            html.Strong("Is Default:"),
                            html.Span(str(current_access.get("isDefault", "N/A")), className="ms-2")
                        ], className="mb-2"),
                    ], width=6),
                    dbc.Col([
                        html.Div([
                            DashIconify(icon="mdi:state-machine", className="me-2"),
                            html.Strong("State:"),
                            html.Span(current_access.get("state", "N/A"), className="ms-2 text-success")
                        ], className="mb-2"),
                        html.Div([
                            DashIconify(icon="mdi:account", className="me-2"),
                            html.Strong("User:"),
                            html.Span(current_access.get("user", {}).get("name", "N/A"), className="ms-2")
                        ], className="mb-2"),
                        html.Div([
                            DashIconify(icon="mdi:domain", className="me-2"),
                            html.Strong("Tenant ID:"),
                            html.Span(current_access.get("tenantId", "N/A"), className="ms-2")
                        ], className="mb-2"),
                        html.Div([
                            DashIconify(icon="mdi:home", className="me-2"),
                            html.Strong("Home Tenant ID:"),
                            html.Span(current_access.get("homeTenantId", "N/A"), className="ms-2")
                        ], className="mb-2"),
                    ], width=6)
                ]),
            ]
            
            info_output_div.append(
                dbc.Card(
                    dbc.CardBody([
                        html.H4([
                            DashIconify(icon="mdi:microsoft-azure", className="me-2"),
                            "Access: ",
                            html.Span("ACTIVE SESSION", className="text-success")
                        ], className="card-title mb-3"),
                        *card_content
                    ]),
                    className="mb-3 text-white"
                )
            )
        else:
            info_output_div.append(
                dbc.Card(
                    dbc.CardBody([
                        html.H4([
                            DashIconify(icon="mdi:microsoft-azure", className="me-2"),
                            "Access: ",
                            html.Span("NO ACTIVE SESSION", className="text-danger")
                        ], className="card-title")
                    ]),
                    className="mb-3 text-white"
                )
            )
    except:
        info_output_div.append(
            dbc.Card(
                dbc.CardBody([
                    html.H4([
                        DashIconify(icon="mdi:microsoft-azure", className="me-2"),
                        "Access: ",
                        html.Span("NO ACTIVE SESSION", className="text-danger")
                    ], className="card-title")
                ]),
                className="mb-3 text-white"
            )
        )

    return info_output_div