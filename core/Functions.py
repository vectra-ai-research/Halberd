import yaml
import csv
import os
import sys
import shutil
import json
from typing import Union, Any, Optional
import datetime
from pathlib import Path
from dash import html, dcc, Patch, dash_table
import dash_daq as daq
import dash_cytoscape as cyto
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify
import pandas as pd
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
                    html.P(f"Sub-Technique: {mitre_info.sub_technique_name}", className="card-text"),
                    html.P(f"Tactic: {', '.join(mitre_info.tactics)}", className="card-text"),
                    dcc.Link("Visit MITRE", href=mitre_info.mitre_url if mitre_info.mitre_url not in [None, "#"] else "#", target="_blank", className="halberd-link")
                ])
            ], className="mb-2 halberd-depth-card")
            mitre_cards.append(mitre_card)
        return html.Div(mitre_cards)
    
    def create_azure_trm_info_cards(azure_trm_techniques):
        """Create dbc.cards with technique Azure Threat Research Matrix info"""
        mitre_cards = []
        for azure_trm_info in azure_trm_techniques:
            mitre_card = dbc.Card([
                dbc.CardBody([
                    html.P(f"Technique: {azure_trm_info.technique_name}", className="card-text"),
                    html.P(f"Sub-Technique: {azure_trm_info.sub_technique_name}", className="card-text"),
                    html.P(f"Tactic: {', '.join(azure_trm_info.tactics)}", className="card-text"),
                    dcc.Link("Visit Azure Threat Research Matrix", href=azure_trm_info.azure_trm_url if azure_trm_info.azure_trm_url not in [None, "#"] else "#", target="_blank", className="halberd-link")
                ])
            ], className="mb-2 halberd-depth-card")
            mitre_cards.append(mitre_card)
        return html.Div(mitre_cards)
    
    # Get technique information from technique registry
    technique = TechniqueRegistry.get_technique(technique_id)()
    technique_category = TechniqueRegistry.get_technique_category(technique_id)

    # Main technique information card
    main_info_card = dbc.Card([
        dbc.CardHeader(html.Div(technique.name, className="mb-0 halberd-brand text-2xl")),
        dbc.CardBody([
            html.Span(CATEGORY_MAPPING.get(technique_category, technique_category), className=f"tag tag-{CATEGORY_MAPPING.get(technique_category, technique_category).lower()} mb-3"),
            html.H5("Description:", className="mb-2 halberd-typography"),
            html.P(technique.description, className="mb-3 halberd-text")
        ])
    ], className="mb-3 halberd-depth-card")

    modal_content = [main_info_card]
    
    modal_content.append(
        dbc.Accordion([
            dbc.AccordionItem(create_mitre_info_cards(technique.mitre_techniques), title="MITRE ATT&CK Reference", className="halberd-accordion-item")
        ], start_collapsed=False, className="mb-3 halberd-accordion")
    )
    
    # Display Azure threat research matrix info - only for Azure techniques
    if technique_category == "azure":
        if technique.azure_trm_techniques:
            modal_content.append(
                dbc.Accordion([
                    dbc.AccordionItem(create_azure_trm_info_cards(technique.azure_trm_techniques), title="Azure Threat Research Matrix Reference")
                ], start_collapsed=True, className="mb-3 halberd-accordion")
            )
    
    # Technique notes
    if technique.notes:
        modal_content.append(
            dbc.Accordion([
                dbc.AccordionItem(
                    [html.Li(note.note) for note in technique.notes],
                    title="Technique Notes"
                )
            ], start_collapsed=True, className="mb-3 halberd-accordion")
        )

    # Technique references
    if technique.references:
        modal_content.append(
            dbc.Accordion([
                dbc.AccordionItem(
                    [html.Li(dcc.Link(ref.title, href=ref.link if ref.link not in [None, "#"] else "#", target="_blank", className="halberd-link")) for ref in technique.references],
                    title="Technique References"
                )
            ], start_collapsed=True, className="mb-3 halberd-accordion")
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

def playbook_viz_generator(playbook_name: Optional[str]) -> html.Div:
    """
    Generate a vertical visualization of a playbook's attack sequence.
    
    Args:
        playbook_name (Optional[str]): The name of the playbook to visualize.
            If None, a "No Selection" message is displayed.

    Returns:
        html.Div: A container with both the graph and its legend
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

        # Attack surface configuration
        surface_colors = {
            'entra_id': '#4B77BE',
            'm365': '#45B39D',
            'azure': '#5D6D7E',
            'aws': '#D4AC0D'
        }
        
        # Initialize arrays
        attack_sequence_viz_elements = []
        n = 0
        position_y = 100

        # Base spacing
        step_spacing = 150
        base_x = 300
        total_steps = len(pb_config.data['PB_Sequence'])

        # Create nodes
        for step_no, step in pb_config.data['PB_Sequence'].items():
            step_no = int(step_no)
            step_module_id = step['Module']
            step_wait = step['Wait']
            category = TechniqueRegistry.get_technique_category(step_module_id)
            
            # Add technique node
            attack_sequence_viz_elements.append({
                'data': {
                    'id': str(n),
                    'label': f"Step {step_no}\n{TechniqueRegistry.get_technique(step_module_id)().name}",
                    'category': category,
                    'info':{step_no: step}
                },
                'position': {'x': base_x, 'y': position_y}
            })
            n += 1

            # Add time node if not last step
            if step_no < total_steps:
                attack_sequence_viz_elements.append({
                    'data': {
                        'id': str(n),
                        'label': f"{step_wait}s",
                        'time': True,
                        'info':"time"
                    },
                    'position': {'x': base_x, 'y': position_y + step_spacing/2},
                    'classes': 'timenode'
                })
                n += 1
            
            position_y += step_spacing

        # Create edges
        for i in range(len(attack_sequence_viz_elements) - 1):
            attack_sequence_viz_elements.append({
                'data': {
                    'source': str(i),
                    'target': str(i + 1)
                }
            })

        # Stylesheet
        stylesheet = [
            {
                'selector': 'node',
                'style': {
                    'label': 'data(label)',
                    'width': '300px',
                    'height': '80px',
                    'text-halign': 'center',
                    'text-valign': 'center',
                    'shape': 'rectangle',
                    'background-color': '#FFFFFF',
                    'color': '#000000',
                    'font-size': '16px',
                    'text-wrap': 'wrap',
                    'font-weight': 'bold'
                }
            }
        ]
        
        # Add surface colors
        for surface, color in surface_colors.items():
            stylesheet.append({
                'selector': f'node[category = "{surface}"]',
                'style': {
                    'background-color': color,
                    'color': '#ffffff'
                }
            })
        
        # Additional styles
        stylesheet.extend([
            {
                'selector': '.timenode',
                'style': {
                    'label': 'data(label)',
                    'background-color': '#2b2b2b',
                    'color': '#ffffff',
                    'width': '40px',
                    'height': '40px',
                    'shape': 'diamond'
                }
            },
            {
                'selector': 'edge',
                'style': {
                    'curve-style': 'straight',
                    'target-arrow-shape': 'triangle',
                    'line-color': '#525252',
                    'target-arrow-color': '#525252',
                    'width': 2
                }
            }
        ])

        # Attack surface legend
        legend_items = []
        used_surfaces = {node['data']['category'] for node in attack_sequence_viz_elements 
                        if 'data' in node and 'category' in node['data']}
        
        for surface in used_surfaces:
            if surface in surface_colors:
                legend_items.append(
                    html.Div([
                        html.Div(style={
                            'backgroundColor': surface_colors[surface],
                            'width': '20px',
                            'height': '20px',
                            'marginRight': '8px',
                            'display': 'inline-block'
                        }),
                        html.Span(surface.replace('_', ' ').upper(), 
                                style={'color': 'white'})
                    ], style={'marginRight': '20px', 'display': 'inline-block'})
                )

        # Return layout
        return html.Div([
            # Legend
            html.Div(
                legend_items,
                style={
                    'padding': '5px',
                    'display': 'flex',
                    'alignItems': 'center',
                    'justifyContent': 'center',
                },
                className="halberd-typography mb-0 halberd-depth-card"
            ),
            # Graph
            cyto.Cytoscape(
                id='auto-attack-sequence-cytoscape-nodes',
                layout={'name': 'preset'},
                style={
                    'width': '100%',
                    'height': '65vh'
                },
                elements=attack_sequence_viz_elements,
                stylesheet=stylesheet,
                userZoomingEnabled=True,
                userPanningEnabled=True,
                minZoom=0.5,
                maxZoom=2
            )
        ])

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
                "label": html.Div([tactic],className="halberd-text"),
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
                            "label": html.Div([technique().name], style={"padding-left": "10px","padding-top": "5px", "padding-bottom": "5px"}),
                            "value": technique_module,
                        }
                    )

    technique_options_element = [
        dcc.RadioItems(
            id = "attack-options-radio", 
            options = technique_options_list, 
            value = technique_options_list[0]["value"], 
            labelStyle={"display": "flex", "align-items": "center"},
            className="halberd-radio"
        )
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
                config_div_elements.append(dbc.Label(input_config['name']+" *", className="halberd-text"))
            else:
                config_div_elements.append(dbc.Label(input_config['name'], className="halberd-text"))

            if input_config['input_field_type'] in ["text", "email", "password", "number"]:
                config_div_elements.append(dbc.Input(
                    type = input_config['input_field_type'],
                    placeholder = input_config['default'] if input_config['default'] else "", #default param value in placeholder
                    debounce = True,
                    id = {"type": "technique-config-display", "index": input_field},
                    className="bg-halberd-dark border halberd-text halberd-input",
                ))
            elif input_config['input_field_type'] == "bool":
                config_div_elements.append(
                    daq.BooleanSwitch(
                        id = {"type": "technique-config-display-boolean-switch", "index": input_field}, 
                        on=input_config['default']
                    )
                )
            elif input_config['input_field_type'] == "upload":
                config_div_elements.append(dcc.Upload(
                    id = {"type": "technique-config-display-file-upload", "index": input_field}, 
                    children=html.Div([html.A('Select a file or Drag one here', className="halberd-link")]), 
                    className="bg-halberd-dark halberd-input",
                    style={'width': '50%', 'height': '60px', 'lineHeight': '60px', 'borderWidth': '1px', 'borderStyle': 'dashed', 'borderRadius': '5px', 'textAlign': 'center', 'margin': '10px'})
                )
                
            config_div_elements.append(html.Br())

        config_div = html.Div(config_div_elements, className='d-grid col-6 mx-auto', style={'width' : '100%'})
        config_div_display.append(config_div)
    else:
        config_div_display.append(
            html.Div(html.P("No config required! Hit 'Execute Technique'"), className='halberd-text d-grid col-6 mx-auto text-center', style={'width' : '100%'})
        )

    # Add access button
    config_div_display.append(dbc.Label("Execute As", className="halberd-text"))
    config_div_display.append(
            dbc.Button(
                "Establish Access", 
                id="attack-access-info-dynamic-btn", 
                color="success", 
                className="mb-3",
                outline=True,
                style = {
                    'width': '20vw',
                    'display': 'flex',
                    'justify-content': 'center',
                    'align-items': 'center'
                }
            )
        )

    config_div_display.append(html.Br())
    
    # Add technique execute button
    config_div_display.append(
        (html.Div([
            dbc.Button([
                DashIconify(
                    icon="mdi:play",
                    width=20,
                    className="me-2"
                ),
                "Execute Technique"
            ],
            id="technique-execute-button",
            n_clicks=0,
            className="halberd-button mb-3"
            )
        ], className="d-grid col-3 mx-auto halberd-text"))
    )

    # Add add to playbook button
    config_div_display.append(
        html.Div([
            dbc.Button(
                [
                    DashIconify(
                        icon="mdi:plus",
                        width=20,
                        className="me-2"
                    ),
                    "Add to Playbook"
                ],
                id="open-add-to-playbook-modal-button", 
                n_clicks=0, 
                className="halberd-button-secondary"
            )
        ], style={'display': 'flex', 'justify-content': 'center', 'gap': '10px'}, className="halberd-text")
    )
    
    # Create plabook modal dropdown content
    playbook_dropdown_options = []    
    for pb in GetAllPlaybooks():
        playbook_dropdown_options.append(
            {
                "label": html.Div([Playbook(pb).name], style={'font-size': 20}, className="halberd-text"),
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
                        className="halberd-dropdown halberd-text"
                        ),
                    html.Br(),
                    dbc.Label("Add to Step # (Optional)", className="text-light"),
                    dbc.Input(id='pb-add-step-number-input', placeholder="3", type= "number", className="bg-halberd-dark text-light halberd-input"),
                    html.Br(),
                    dbc.Label("Wait in Seconds After Step Execution (Optional)", className="text-light"),
                    dbc.Input(id='pb-add-step-wait-input', placeholder="120", type= "number", className="bg-halberd-dark text-light halberd-input")
                ]),
                dbc.ModalFooter([
                    dbc.Button("Cancel", id="close-add-to-playbook-modal-button", className="ml-auto halberd-button-secondary", n_clicks=0),
                    dbc.Button("Add to Playbook", id="confirm-add-to-playbook-modal-button", className="ml-2 halberd-button", n_clicks=0)
                ])
            ],
            id="add-to-playbook-modal",
            is_open=False,
            className="halberd-text"
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

def parse_app_log_file(file_path):
    """Function to parse the app log file"""
    events = []
    with open(file_path, 'r') as file:
        next(file)  # Skip the header line
        for line in file:
            if "Technique Execution" in line:
                parts = line.split(" - INFO - Technique Execution ")
                timestamp = parts[0].split(',')[0]
                event_data = json.loads(parts[1])
                event_data['log_timestamp'] = timestamp
                events.append(event_data)
    return events[::-1]  # Reverse the list to show newest first

def group_app_log_events(events):
    """Function to group multiple logs linked to an event"""
    grouped = {}
    for event in events:
        event_id = event['event_id']
        if event_id not in grouped:
            grouped[event_id] = []
        grouped[event_id].append(event)
    return grouped

def create_app_log_event_summary(grouped_events):
    """Function to create summary of events from multiple log lines"""
    summary = []
    for event_id, events in grouped_events.items():
        start_event = next((e for e in events if e['status'] == 'started'), None)
        end_event = next((e for e in events if e['status'] in ['completed', 'failed']), None)
        
        if start_event and end_event:
            summary.append({
                'Technique': start_event.get('technique', 'N/A'),
                'Source': start_event.get('source', 'Unknown'),
                'Start Time': start_event['log_timestamp'],
                'Result': end_event.get('result', 'N/A'),
                'Tactic': start_event.get('tactic', 'N/A'),
                'Event ID': event_id    
            })
    return summary

def generate_attack_trace_table():
    """Function to generate the attack trace table view"""
    
    # Parse log file and create summary
    events = parse_app_log_file(APP_LOG_FILE)
    grouped_events = group_app_log_events(events)
    summary = create_app_log_event_summary(grouped_events)

    # Create DataFrame
    df = pd.DataFrame(summary)

    # Return app layout
    return html.Div([
        dash_table.DataTable(
            id='trace-table',
            columns=[{"name": i, "id": i, "presentation": "markdown" if i == "Output" else None} for i in df.columns],
            data=df.to_dict('records'),
            style_table={
                'overflowX': 'auto',
                'backgroundColor': '#2F4F4F'
            },
            style_data={
                'backgroundColor': '#1a1a1a',
                'color': 'white',
                'border': '1px solid #3a3a3a',
                'height': '50px',  # Row height
                'lineHeight': '40px',
                'whiteSpace': 'normal',  # Wrap text
                'minWidth': '150px',  # Minimum width per column
                'padding': '10px'  # Add some padding
            },
            style_cell={
                'textAlign': 'left',
                'backgroundColor': '#1a1a1a',
                'color': 'white',
                'border': '1px solid #3a3a3a'
            },
            style_header={
                'backgroundColor': '#2b2b2b',
                'fontWeight': 'bold',
                'border': '1px solid #3a3a3a'
            },
            style_data_conditional=[
                {
                    'if': {'row_index': 'odd'},
                    'backgroundColor': '#202020',
                },
                {
                    'if': {'state': 'selected'},
                    'backgroundColor': '#363636',
                    'border': '1px solid #3a3a3a',
                },
                {
                    'if': {'state': 'active'},
                    'backgroundColor': '#363636',
                    'border': '1px solid #3a3a3a',
                }
            ],
            style_filter={
                'backgroundColor': '#2b2b2b',
                'color': 'white',  # Text color for the filter input
            },
            style_filter_conditional=[{
                'if': {'column_id': c},
                'backgroundColor': '#2b2b2b',
                'color': 'white',
            } for c in df.columns],
            sort_action='native',
            row_selectable='single',
            filter_action = 'native',
            page_size=5,
            markdown_options={"html": True}  # Allow HTML in markdown
        ),
    ], 
    className="bg-halberd-dark halberd-text")

def get_playbook_stats():
    """
    Get statistics about playbooks in the system.
    
    Returns:
        dict: Dictionary containing:
            - total_playbooks: Total number of playbooks
            - last_sync: Timestamp of most recently modified playbook
    """
    try:
        playbooks = GetAllPlaybooks()
        total_playbooks = len(playbooks)
        last_modified = None
        
        for pb in playbooks:
            try:
                config = Playbook(pb)
                
                # Check last modified time
                pb_modified = os.path.getmtime(config.yaml_file_path)
                if last_modified is None or pb_modified > last_modified:
                    last_modified = pb_modified
                    
            except Exception as e:
                print(f"Error processing playbook {pb}: {str(e)}")
                continue
        
        return {
            "total_playbooks": total_playbooks,
            "last_sync": datetime.datetime.fromtimestamp(last_modified) if last_modified else None
        }
        
    except Exception as e:
        print(f"Error getting playbook stats: {str(e)}")
        return {
            "total_playbooks": 0,
            "last_sync": None
        }
    
def parse_execution_report(execution_folder):
    """Parse the execution report CSV file"""
    report_file = os.path.join(execution_folder, "Report.csv")
    
    if not os.path.exists(report_file):
        return []
        
    results = []
    try:
        with open(report_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('Time_Stamp') != 'Time_Stamp':
                    results.append({
                        'module': row.get('Module'),
                        'status': row.get('Result'),
                        'timestamp': row.get('Time_Stamp')
                    })
    except Exception as e:
        print(f"Error parsing report: {str(e)}")
        return []
        
    return results