import base64
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
from core.gcp.gcp_access import GCPAccess
from attack_techniques.technique_registry import TechniqueRegistry
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.oauth2.credentials import Credentials as UserAccountCredentials
from google.auth.exceptions import RefreshError


def generate_technique_info(technique_id)-> list:
    """
    Generates list of elements containing technique information that can be displayed inside any other html element. 
    """
    def create_mitre_info_cards(mitre_techniques):
        """Create dbc.cards with technique MITRE info"""
        if not mitre_techniques:
            return html.Div([
                html.P("No MITRE ATT&CK techniques found.", className="text-muted text-center py-3")
            ])
        
        mitre_cards = []
        for idx, mitre_info in enumerate(mitre_techniques):
            # Create tactics badges
            tactic_badges = [
                dbc.Badge(
                    tactic, 
                    color="danger", 
                    className="me-1 mb-1",
                    style={
                        "fontSize": "0.75rem",
                        "fontWeight": "500",
                        "textTransform": "uppercase",
                        "letterSpacing": "0.5px"
                    }
                ) for tactic in mitre_info.tactics
            ]
            
            mitre_card = dbc.Card([
                dbc.CardBody([
                    # Header with technique ID and external link icon
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.I(className="fas fa-shield-alt me-2", style={"color": "#dc3545"}),
                                html.Strong(
                                    mitre_info.technique_id, 
                                    className="halberd-brand",
                                    style={"fontSize": "0.9rem", "color": "#dc3545"}
                                )
                            ], className="mb-2")
                        ], width=8),
                        dbc.Col([
                            dbc.Button([
                                html.I(className="fas fa-external-link-alt me-1"),
                                "MITRE"
                            ],
                            href=mitre_info.mitre_url if mitre_info.mitre_url not in [None, "#"] else "#",
                            target="_blank",
                            color="outline-danger",
                            size="sm",
                            className="float-end",
                            style={
                                "fontSize": "0.75rem",
                                "borderRadius": "4px",
                                "transition": "all 0.2s ease"
                            })
                        ], width=4)
                    ], className="mb-2"),
                    
                    # Technique name
                    html.H6(
                        mitre_info.technique_name, 
                        className="mb-2",
                        style={
                            "color": "#ffffff",
                            "fontWeight": "600",
                            "lineHeight": "1.3"
                        }
                    ),
                    
                    # Sub-technique (if exists)
                    html.Div([
                        html.Small([
                            html.I(className="fas fa-sitemap me-1", style={"color": "#6c757d"}),
                            f"Sub-Technique: {mitre_info.sub_technique_name}"
                        ], className="text-muted mb-2 d-block")
                    ] if mitre_info.sub_technique_name and mitre_info.sub_technique_name != "None" else []),
                    
                    # Tactics section
                    html.Div([
                        html.Small("Tactics:", className="text-muted d-block mb-1"),
                        html.Div(tactic_badges, className="d-flex flex-wrap")
                    ])
                ])
            ], 
            className="mb-2 halberd-depth-card technique-card",
            style={
                "transition": "all 0.3s ease",
                "border": "1px solid rgba(220, 53, 69, 0.2)",
                "background": "linear-gradient(135deg, rgba(33, 37, 41, 0.95) 0%, rgba(52, 58, 64, 0.95) 100%)"
            },
            id=f"mitre-card-{idx}")
            
            mitre_cards.append(mitre_card)
        
        return html.Div(mitre_cards, className="mitre-cards-container")
    
    def create_azure_trm_info_cards(azure_trm_techniques):
        """Create dbc.cards with technique Azure Threat Research Matrix info"""
        azure_cards = []
        for idx, azure_trm_info in enumerate(azure_trm_techniques):
            # Create tactics badges
            tactic_badges = [
                dbc.Badge(
                    tactic, 
                    color="info", 
                    className="me-1 mb-1",
                    style={
                        "fontSize": "0.75rem",
                        "fontWeight": "500",
                        "textTransform": "uppercase",
                        "letterSpacing": "0.5px"
                    }
                ) for tactic in azure_trm_info.tactics
            ]
            
            azure_card = dbc.Card([
                dbc.CardBody([
                    # Header with technique ID and external link icon
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.I(className="fab fa-microsoft me-2", style={"color": "#0078d4"}),
                                html.Strong(
                                    azure_trm_info.technique_id, 
                                    className="halberd-brand",
                                    style={"fontSize": "0.9rem", "color": "#0078d4"}
                                )
                            ], className="mb-2")
                        ], width=8),
                        dbc.Col([
                            dbc.Button([
                                html.I(className="fas fa-external-link-alt me-1"),
                                "Azure TRM"
                            ],
                            href=azure_trm_info.azure_trm_url if azure_trm_info.azure_trm_url not in [None, "#"] else "#",
                            target="_blank",
                            color="outline-info",
                            size="sm",
                            className="float-end",
                            style={
                                "fontSize": "0.75rem",
                                "borderRadius": "4px",
                                "transition": "all 0.2s ease"
                            })
                        ], width=4)
                    ], className="mb-2"),
                    
                    # Technique name
                    html.H6(
                        azure_trm_info.technique_name, 
                        className="mb-2",
                        style={
                            "color": "#ffffff",
                            "fontWeight": "600",
                            "lineHeight": "1.3"
                        }
                    ),
                    
                    # Sub-technique (if exists)
                    html.Div([
                        html.Small([
                            html.I(className="fas fa-sitemap me-1", style={"color": "#6c757d"}),
                            f"Sub-Technique: {azure_trm_info.sub_technique_name}"
                        ], className="text-muted mb-2 d-block")
                    ] if azure_trm_info.sub_technique_name and azure_trm_info.sub_technique_name != "None" else []),
                    
                    # Tactics section
                    html.Div([
                        html.Small("Tactics:", className="text-muted d-block mb-1"),
                        html.Div(tactic_badges, className="d-flex flex-wrap")
                    ])
                ])
            ], 
            className="mb-2 halberd-depth-card technique-card",
            style={
                "transition": "all 0.3s ease",
                "border": "1px solid rgba(0, 120, 212, 0.2)",
                "background": "linear-gradient(135deg, rgba(33, 37, 41, 0.95) 0%, rgba(52, 58, 64, 0.95) 100%)"
            },
            id=f"azure-card-{idx}")
            
            azure_cards.append(azure_card)
        
        return html.Div(azure_cards, className="azure-cards-container")
    
    # Get technique information from technique registry
    technique = TechniqueRegistry.get_technique(technique_id)()
    technique_category = TechniqueRegistry.get_technique_category(technique_id)

    # Main technique information card
    main_info_card = dbc.Card([
        dbc.CardHeader([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.I(
                            className="fas fa-crosshairs me-3", 
                            style={
                                "color": "#dc3545", 
                                "fontSize": "1.5rem",
                                "verticalAlign": "middle"
                            }
                        ),
                        html.Span(
                            technique.name, 
                            className="halberd-brand",
                            style={
                                "fontSize": "1.4rem",
                                "fontWeight": "700",
                                "color": "#ffffff",
                                "verticalAlign": "middle"
                            }
                        )
                    ], className="d-flex align-items-center")
                ], lg=8, md=12),
                dbc.Col([
                    dbc.Badge(
                        CATEGORY_MAPPING.get(technique_category, technique_category).upper(),
                        color="secondary",
                        className="float-end technique-category-badge",
                        style={
                            "fontSize": "0.8rem",
                            "fontWeight": "600",
                            "letterSpacing": "1px",
                            "padding": "8px 16px",
                            "borderRadius": "20px",
                            "background": "linear-gradient(45deg, #6c757d 0%, #495057 100%)",
                            "border": "none",
                            "boxShadow": "0 2px 4px rgba(0,0,0,0.2)"
                        }
                    )
                ], lg=4, md=12, className="text-end mt-2 mt-lg-0")
            ], align="center")
        ], style={
            "background": "linear-gradient(135deg, rgba(220, 53, 69, 0.1) 0%, rgba(108, 117, 125, 0.1) 100%)",
            "borderBottom": "2px solid rgba(220, 53, 69, 0.3)"
        }),
        dbc.CardBody([
            html.Div([
                html.I(className="fas fa-info-circle me-2", style={"color": "#6c757d"}),
                html.Strong("Description", style={"color": "#ffffff", "fontSize": "1rem"})
            ], className="mb-3"),
            html.P(
                technique.description, 
                className="halberd-text",
                style={
                    "fontSize": "0.95rem",
                    "lineHeight": "1.6",
                    "color": "#e9ecef",
                    "marginBottom": "0"
                }
            )
        ])
    ], 
    className="mb-4 halberd-depth-card main-technique-card",
    style={
        "border": "1px solid rgba(220, 53, 69, 0.3)",
        "background": "linear-gradient(135deg, rgba(33, 37, 41, 0.98) 0%, rgba(52, 58, 64, 0.98) 100%)",
        "boxShadow": "0 8px 32px rgba(0, 0, 0, 0.3)"
    })

    modal_content = [main_info_card]
    
    modal_content.append(
        dbc.Accordion([
            dbc.AccordionItem(create_mitre_info_cards(technique.mitre_techniques),
             title="MITRE ATT&CK Reference")
            
        ], start_collapsed=False, className="mb-3 enhanced-accordion"
        )
    )
    
    # Display Azure threat research matrix info - only for Azure techniques
    if technique_category == "azure":
        if technique.azure_trm_techniques:
            modal_content.append(
                dbc.Accordion([
                    dbc.AccordionItem(create_azure_trm_info_cards(technique.azure_trm_techniques), title="Azure Threat Research Matrix Reference")
                ], start_collapsed=True, className="mb-3 enhanced-accordion"
                )
            )
    
    # Technique notes
    if technique.notes:
        notes_content = []
        for idx, note in enumerate(technique.notes):
            notes_content.append(
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fas fa-sticky-note me-2", style={"color": "#ffc107"}),
                            html.Span(note.note, style={"color": "#e9ecef", "fontSize": "0.9rem"})
                        ])
                    ])
                ], className="mb-2", 
                style={
                    "border": "1px solid rgba(255, 193, 7, 0.2)"
                })
            )
        modal_content.append(
            dbc.Accordion([
                dbc.AccordionItem(
                    notes_content,
                    title="Technique Notes"
                )
            ], start_collapsed=True, className="mb-3 enhanced-accordion",
            style={
                "overflow": "hidden"
            })
        )

    # Technique references
    if technique.references:
        references_content = []
        for idx, ref in enumerate(technique.references):
            references_content.append(
                dbc.Card([
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                html.I(className="fas fa-link me-2", style={"color": "#17a2b8"}),
                                dcc.Link(
                                    ref.title, 
                                    href=ref.link if ref.link not in [None, "#"] else "#", 
                                    target="_blank", 
                                    className="halberd-link",
                                    style={
                                        "color": "#17a2b8",
                                        "textDecoration": "none",
                                        "fontSize": "0.9rem",
                                        "fontWeight": "500"
                                    }
                                )
                            ], width=10),
                            dbc.Col([
                                html.I(
                                    className="fas fa-external-link-alt", 
                                    style={"color": "#6c757d", "fontSize": "0.8rem"}
                                )
                            ], width=2, className="text-end")
                        ], align="center")
                    ])
                ], className="mb-2", 
                style={
                    "border": "1px solid rgba(23, 162, 184, 0.2)",
                    "transition": "all 0.2s ease"
                })
            )

        modal_content.append(
            dbc.Accordion([
                dbc.AccordionItem(
                    references_content,
                    title="Technique References"
                )
            ], 
            start_collapsed=True, 
            className="mb-3 enhanced-accordion",
            style={
                "overflow": "hidden"
            })
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
            'aws': '#D4AC0D',
            'gcp': '#E74C3C'
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

        # Calculate node size based on maximum label length among nodes so all nodes follow the same max size
        max_label_len = 0
        for el in attack_sequence_viz_elements:
            if isinstance(el, dict) and 'data' in el:
                lab = el.get('data', {}).get('label', '')
                if isinstance(lab, str):
                    # count characters (including newline characters)
                    lab_len = len(lab.replace('\n', ' '))
                    if lab_len > max_label_len:
                        max_label_len = lab_len

        # Estimate pixel width per character and clamp to reasonable bounds
        px_per_char = 8  # approximate average character width in pixels
        # Minimum width ensures small labels still produce a readable node
        min_width_px = 160
        # Maximum width to avoid overly large nodes
        max_width_cap = 800
        max_width_px = max(min_width_px, min(max_width_cap, int(max_label_len * px_per_char)))

        # Keep node height fixed while adjusting width to fit the longest label
        node_height_px = 80

        # Stylesheet uses the calculated width so all nodes will follow the maximum module label size
        stylesheet = [
            {
                'selector': 'node',
                'style': {
                    'label': 'data(label)',
                    'width': f'{max_width_px}px',
                    'height': f'{node_height_px}px',
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
    if tab == "tab-attack-GCP":
        tactics_options = technique_registry.list_tactics("gcp")
    
    # Create the dropdown element
    tactic_dropdown_option = []    
    for tactic in tactics_options:
        tactic_dropdown_option.append(
            {
                "label": html.Div([tactic],className="halberd-brand"),
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
    elif tab == "tab-attack-GCP":
        attack_surface_techniques = technique_registry.list_techniques("gcp")
        
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
                            "label": html.Div([technique().name], className="halberd-brand"),
                            "value": technique_module,
                        }
                    )
    
    return technique_options_list

def generate_attack_technique_config(technique, mode="attack", existing_values={}, step_index=None, id_type=None):
    """
    Function generates the technique configuration view for both attack and automator pages. 
    Converts technique inputs into UI input fields with styling and interactions.
    
    :param technique: Exact name of technique in Halberd technique registry
    :param mode: "attack" for quick execution with Execute/Add to Playbook buttons, 
                 "automator" for playbook creation (parameters only, no action buttons),
    :param existing_values: Dictionary of existing parameter values to pre-fill input fields
    :param id_type: Optional type for component IDs. 
    """
    technique_obj = TechniqueRegistry.get_technique(technique)()
    
    technique_config = technique_obj.get_parameters()

    # Use Patch only for attack mode, use regular list for automator mode
    config_div_display = Patch() if mode == "attack" else []
    if mode == "attack":
        config_div_display.clear()
    
    # Determine ID type based on mode
    # Determine ID type prefix based on id_type parameter
    
    # id_type = "technique-config-display" if mode == "attack" else "param-input"
    # id_index_key = "index" if mode == "attack" else "param"
    

    # Configure header (only for attack mode)
    if mode == "attack":
        config_header = html.Div([
            html.Div([
                html.Div([
                    html.I(
                        className="fas fa-cog me-3", 
                        style={
                            "color": "#dc3545", 
                            "fontSize": "1.1rem",
                            "animation": "spin 3s linear infinite"
                        }
                    ),
                    html.Span(
                        "Configure & Execute", 
                        className="halberd-brand",
                        style={
                            "fontSize": "1.1rem",
                            "fontWeight": "700",
                            "color": "#ffffff",
                            "letterSpacing": "0.5px"
                        }
                    ),
                    html.I(
                        id="config-arrow",
                        className="fas fa-chevron-down config-arrow ms-auto",
                        style={
                            "color": "#dc3545",
                            "fontSize": "1rem",
                            "transition": "transform 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
                            "cursor": "pointer"
                        }
                    )
                ], className="d-flex align-items-center w-100")
            ], className="d-flex justify-content-between align-items-center w-100")
        ], 
        id="config-header",
        className="enhanced-config-header px-3 py-3",
        style={
            "background": "linear-gradient(135deg, rgba(220, 53, 69, 0.15) 0%, rgba(108, 117, 125, 0.15) 100%)",
            "borderBottom": "2px solid rgba(220, 53, 69, 0.3)",
            "borderRadius": "8px 8px 0 0",
            "cursor": "pointer",
            "transition": "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
            "position": "relative",
            "overflow": "hidden",
            "border": "1px solid rgba(220, 53, 69, 0.2)"
        })

        config_div_display.append(config_header)

    # Collapsible Configuration Content
    config_content = []

    # Check if technique requires input
    if len(technique_config.keys()) > 0:
        config_form_elements = []

        # Configuration Form Header
        config_form_elements.append(
            html.Div([
                html.Div([
                    html.I(className="fas fa-wrench me-2", style={"color": "#6c757d", "fontSize": "0.9rem"}),
                    html.Span("Technique Parameters", style={"fontSize": "0.9rem", "fontWeight": "600"})
                ], className="text-muted mb-3")
            ])
        )

        # Parameter Grid
        param_grid = []
        for input_field, input_config in technique_config.items():
            param_row = html.Div([
                # Parameter Label
                html.Div([
                    html.Label([
                        html.Span(input_config['name'], style={"fontWeight": "600"}),
                        html.Span(" *", style={"color": "#dc3545", "fontWeight": "bold"}) if input_config['required'] else "",
                        html.Small(
                            f" ({input_config.get('description', 'Parameter configuration')})",
                            className="text-muted ms-2",
                            style={"fontSize": "0.75rem", "fontStyle": "italic"}
                        ) if input_config.get('description') else ""
                    ], 
                    className="halberd-text enhanced-param-label",
                    style={"marginBottom": "8px", "display": "block"}
                    )
                ], className="mb-2"),

                # Input Field Container
                html.Div([
                    # Text/Email/Password/Number Inputs
                    html.Div([
                        dbc.Input(
                            type = input_config['input_field_type'],
                            placeholder = f"Default: {input_config['default']}" if input_config['default'] else f"Enter {input_config['name'].lower()}...", 
                            debounce = True,
                            id = ( {"type": "attack-technique-config", "technique": technique ,"param": input_field, "step": step_index, "canvas-type": id_type} if step_index is not None else {"type": "attack-technique-config", "technique": technique ,"param": input_field} ),
                            className="enhanced-param-input",
                            style={
                                "background": "rgba(33, 37, 41, 0.8)",
                                "border": "2px solid rgba(108, 117, 125, 0.3)",
                                "borderRadius": "8px",
                                "color": "#ffffff",
                                "padding": "12px 16px",
                                "fontSize": "0.9rem",
                                "transition": "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
                                "backdropFilter": "blur(5px)"
                            },
                            value = existing_values.get(input_field, "")
                        ),
                    ]) if input_config['input_field_type'] in ["text", "email", "password", "number"] else
                    
                    # Select Dropdown
                    dbc.Select(
                        id = ( {"type": "attack-technique-config", "technique": technique ,"param": input_field, "step": step_index, "canvas-type": id_type} if step_index is not None else {"type": "attack-technique-config", "technique": technique ,"param": input_field} ),
                        options=input_config["input_list"],
                        placeholder = f"Default: {input_config['default']}" if input_config['default'] else f"Select {input_config['name'].lower()}...",
                        className="enhanced-param-select",
                        style={
                            "background": "rgba(33, 37, 41, 0.8)",
                            "border": "2px solid rgba(108, 117, 125, 0.3)",
                            "borderRadius": "8px",
                            "color": "#ffffff",
                            "padding": "8px 12px",
                            "fontSize": "0.9rem",
                            "transition": "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
                            "backdropFilter": "blur(5px)"
                        }
                    ) if input_config['input_field_type'] == "select" else
                    
                    # Boolean Switch
                    html.Div([
                        daq.BooleanSwitch(
                            id = ( {"type": "attack-technique-config", "technique": technique ,"param": input_field, "step": step_index, "canvas-type": id_type} if step_index is not None else {"type": "attack-technique-config", "technique": technique ,"param": input_field} ),
                            on=existing_values.get(input_field, input_config['default']),
                            color="#dc3545",
                            className="enhanced-boolean-switch",
                            style={"transform": "scale(1.2)"}
                        ),
                        html.Span(
                            "True" if existing_values.get(input_field, input_config['default']) else "False",
                            className="text-muted ms-3",
                            style={"fontSize": "0.85rem"}
                        )
                    ], className="d-flex align-items-center") if input_config['input_field_type'] == "bool" else
                    
                    # File Upload
                    html.Div([
                        dcc.Upload(
                            id = ( {"type": "attack-technique-config", "technique": technique ,"param": input_field, "step": step_index, "canvas-type": id_type} if step_index is not None else {"type": "attack-technique-config", "technique": technique ,"param": input_field} ),
                            children=html.Div([
                                html.Div([
                                    html.I(className="fas fa-cloud-upload-alt", style={"fontSize": "2rem", "color": "#6c757d", "marginBottom": "8px"}),
                                    html.Small("Drag and drop or click to select files", className="text-muted"),
                                    html.Div(
                                        id=(
                                            {"type": "attack-technique-config-filename-display", "param": input_field, "step": step_index, "canvas-type": id_type} 
                                            if step_index is not None 
                                            else {"type": "attack-technique-config-filename-display", "param": input_field}
                                        ), 
                                        style={"marginTop": "8px", "color": "#fff", "fontSize": "0.85rem"}
                                    )
                                ], 
                                style={
                                    "display": "flex",
                                    "flexDirection": "column",
                                    "alignItems": "center",
                                    "justifyContent": "center"
                                }, className="text-center"),
                            ], className="enhanced-upload-area"),
                            className="enhanced-file-upload",
                            style={
                                'width': '100%', 
                                'minHeight': '120px', 
                                'background': 'linear-gradient(135deg, rgba(33, 37, 41, 0.6) 0%, rgba(52, 58, 64, 0.6) 100%)',
                                'border': '2px dashed rgba(108, 117, 125, 0.4)',
                                'borderRadius': '12px',
                                'display': 'flex',
                                'alignItems': 'center',
                                'justifyContent': 'center',
                                'transition': 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                                'cursor': 'pointer',
                                'position': 'relative',
                                'overflow': 'hidden'
                            },
                            multiple = input_config.get("multiple_files", False),
                            accept = input_config.get("file_type", "*/*"),
                            contents= existing_values.get(input_field, None),
                        ),
                        html.Small(
                            [
                                html.I(className="fas fa-file me-1", style={"color": "#17a2b8", "fontSize": "0.8rem"}),
                                f"File type: {existing_values[input_field].split(';')[0].replace('data:', '')}"
                            ],
                            className="text-info mt-2 d-block",
                            style={"fontSize": "0.8rem", "fontStyle": "italic"}
                        ) if existing_values.get(input_field) else None
                    ]) if input_config['input_field_type'] == "upload" else html.Div()
                    
                ], className="enhanced-input-container")
                
            ], 
            className="enhanced-param-row mb-4",
            style={
                "padding": "20px",
                "background": "linear-gradient(135deg, rgba(33, 37, 41, 0.4) 0%, rgba(52, 58, 64, 0.4) 100%)",
                "border": "1px solid rgba(108, 117, 125, 0.2)",
                "borderRadius": "12px",
                "backdropFilter": "blur(10px)",
                "transition": "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
                "position": "relative"
            })
            
            param_grid.append(param_row)

        config_form_elements.extend(param_grid)
        
        config_content_div = html.Div(
            config_form_elements, 
            className='enhanced-config-form',
            style={
                'padding': '24px',
                'borderRadius': '0 0 12px 12px',
                'backdropFilter': 'blur(10px)'
            }
        )
        config_content.append(config_content_div)
    else:
        if mode == "attack":
        # No Configuration Required
            config_content.append(
                html.Div([
                    html.Div([
                        html.I(className="fas fa-check-circle", style={"fontSize": "3rem", "color": "#28a745", "marginBottom": "16px"}),
                        html.H5("Ready to Execute", className="halberd-brand mb-3"),
                        html.P("This technique requires no additional configuration.", className="text-muted mb-0")
                    ], className="text-center py-5")
                ], 
                className='enhanced-no-config',
                style={
                    'padding': '24px',
                    'background': 'linear-gradient(135deg, rgba(33, 37, 41, 0.95) 0%, rgba(52, 58, 64, 0.95) 100%)',
                    'borderRadius': '0 0 12px 12px',
                    'backdropFilter': 'blur(10px)'
                })
            )
        else:
            config_content.append(
                html.Div([
                    html.Div([                        
                        html.P("This technique requires no additional configuration.", className="text-muted mb-0")
                    ], className="text-center py-5")
                ], 
                className='enhanced-no-config',
                style={
                    'padding': '24px',
                    'background': 'linear-gradient(135deg, rgba(33, 37, 41, 0.95) 0%, rgba(52, 58, 64, 0.95) 100%)',
                    'borderRadius': '0 0 12px 12px',
                    'backdropFilter': 'blur(10px)'
                })
            )

    # Action Buttons Section (only for attack mode)
    if mode == "attack":
        action_section = html.Div([
            html.Hr(style={"border": "none", "height": "2px", "background": "linear-gradient(90deg, transparent, rgba(220, 53, 69, 0.5), transparent)", "margin": "24px 0"}),
            
            html.Div([
                html.I(className="fas fa-play-circle me-2", style={"color": "#6c757d", "fontSize": "0.9rem"}),
                html.Span("Execute Technique", style={"fontSize": "0.9rem", "fontWeight": "600"})
            ], className="text-muted mb-3"),
            
            html.Div([
                # Primary Execute Button
                dbc.Button([
                    html.Div([
                        html.I(className="fas fa-rocket me-2", style={"fontSize": "1.1rem"}),
                        html.Span("Execute Technique", style={"fontWeight": "600", "fontSize": "1rem"})
                    ], className="d-flex align-items-center justify-content-center"),
                    html.Div([
                        html.Small("Launch attack vector", className="text-muted", style={"fontSize": "0.75rem"})
                    ], className="mt-1")
                ],
                id="technique-execute-button",
                n_clicks=0,
                className="enhanced-execute-button me-3",
                style={
                    'minWidth': '200px',
                    'minHeight': '70px',
                    'background': 'linear-gradient(135deg, #dc3545 0%, #c82333 100%)',
                    'border': 'none',
                    'borderRadius': '12px',
                    'boxShadow': '0 4px 15px rgba(220, 53, 69, 0.4)',
                    'transition': 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                    'position': 'relative',
                    'overflow': 'hidden'
                }),
                
                # Secondary Add to Playbook Button
                dbc.Button([
                    html.Div([
                        html.I(className="fas fa-plus-circle me-2", style={"fontSize": "1rem"}),
                        html.Span("Add to Playbook", style={"fontWeight": "600", "fontSize": "0.95rem"})
                    ], className="d-flex align-items-center justify-content-center"),
                    html.Div([
                        html.Small("Queue for automation", className="text-muted", style={"fontSize": "0.75rem"})
                    ], className="mt-1")
                ],
                id="open-add-to-playbook-modal-button", 
                n_clicks=0, 
                className="enhanced-playbook-button",
                outline=True,
                style={
                    'minWidth': '200px',
                    'minHeight': '70px',
                    'background': 'linear-gradient(135deg, rgba(108, 117, 125, 0.1) 0%, rgba(73, 80, 87, 0.1) 100%)',
                    'border': '2px solid rgba(108, 117, 125, 0.4)',
                    'borderRadius': '12px',
                    'transition': 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                    'position': 'relative',
                    'overflow': 'hidden'
                })
            ], 
            className="d-flex flex-wrap gap-3 justify-content-center",
            style={"marginTop": "20px"}),
            
        ], 
        className="enhanced-action-section",
        style={
            'borderRadius': '0 0 12px 12px',
            'backdropFilter': 'blur(10px)'
        })

        config_content.append(action_section)

    # Collapsible Container (only for attack mode)
    if mode == "attack":
        collapsible_config = dbc.Collapse([
            html.Div(config_content)
        ],
        id="config-collapse",
        is_open=False,
        className="enhanced-config-collapse"
        )

        config_div_display.append(collapsible_config)
    else:
        # For automator mode, display content directly without collapse
        config_div_display.append(html.Div(config_content))
    
    # Create playbook modal dropdown content (only for attack mode)
    if mode == "attack":
        playbook_dropdown_options = []    
        for pb in GetAllPlaybooks():
            playbook_dropdown_options.append(
                {
                    "label": html.Div([Playbook(pb).name], style={'font-size': 16}, className="halberd-text"),
                    "value": Playbook(pb).name,
                }
            )

        # Add to Playbook Modal
        config_div_display.append(
            dbc.Modal([
                dbc.ModalHeader([
                    html.Div([
                        html.I(className="fas fa-list-alt me-2", style={"color": "#dc3545"}),
                        "Add Technique to Playbook"
                    ], className="d-flex align-items-center")
                ], className="enhanced-modal-header"),
                
                dbc.ModalBody([
                    html.Div([
                        html.Label([
                            html.I(className="fas fa-book me-2", style={"color": "#6c757d", "fontSize": "0.9rem"}),
                            "Select Target Playbook"
                        ], className="enhanced-modal-label mb-2"),
                        dcc.Dropdown(
                            options = playbook_dropdown_options, 
                            value = None, 
                            id='att-pb-selector-dropdown',
                            placeholder="Choose a playbook...",
                            className="enhanced-modal-dropdown mb-4",
                            style={
                                "background": "rgba(33, 37, 41, 0.8)",
                                "border": "1px solid rgba(108, 117, 125, 0.3)",
                                "borderRadius": "8px"
                            }
                        ),
                        
                        html.Div([
                            dbc.Col([
                                html.Label([
                                    html.I(className="fas fa-sort-numeric-up me-2", style={"color": "#6c757d", "fontSize": "0.9rem"}),
                                    "Step Position (Optional)"
                                ], className="enhanced-modal-label mb-2"),
                                dbc.Input(
                                    id='pb-add-step-number-input', 
                                    placeholder="e.g., 3", 
                                    type="number", 
                                    className="enhanced-modal-input"
                                )
                            ], md=6),
                            
                            dbc.Col([
                                html.Label([
                                    html.I(className="fas fa-clock me-2", style={"color": "#6c757d", "fontSize": "0.9rem"}),
                                    "Wait Time (seconds)"
                                ], className="enhanced-modal-label mb-2"),
                                dbc.Input(
                                    id='pb-add-step-wait-input', 
                                    placeholder="e.g., 120", 
                                    type="number", 
                                    className="enhanced-modal-input"
                                )
                            ], md=6)
                        ], className="row mb-3")
                        
                    ], className="enhanced-modal-content")
                ], className="enhanced-modal-body"),
                
                dbc.ModalFooter([
                    dbc.Button([
                        html.I(className="fas fa-times me-2"),
                        "Cancel"
                    ], 
                    id="close-add-to-playbook-modal-button", 
                    className="enhanced-modal-cancel-btn", 
                    n_clicks=0,
                    outline=True),
                    
                    dbc.Button([
                        html.I(className="fas fa-plus me-2"),
                        "Add to Playbook"
                    ], 
                    id="confirm-add-to-playbook-modal-button", 
                    className="enhanced-modal-confirm-btn", 
                    n_clicks=0)
                ], className="enhanced-modal-footer")
            ],
            id="add-to-playbook-modal",
            size="lg",
            is_open=False,
            className="enhanced-playbook-modal",
            backdrop="static",
            scrollable=True
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
            className="mb-3"
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
            className="mb-3"
        )
    
    # Handle corrupt tokens
    if access_info is None:
        return dbc.Card(
            dbc.CardBody([
                html.H4("Access Token Status", className="card-title"),
                html.P("Failed to decode access token", className="text-danger")
            ]),
            className="mb-3"
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
        ], className="mt-3 mb-3"),
        
        dbc.Row([
            dbc.Col([
                dbc.Label("Copy Access Token"),
                html.Div([
                    dcc.Clipboard(
                        id="access-token-copy", 
                        title="Copy access token",
                        style={
                            'width': '120px',
                            'textAlign': 'center'
                        },
                        className="halberd-button"
                    ),
                ]),
            ]),
            dbc.Col([
                dbc.Label("Copy Refresh Token"),
                html.Div([
                    dcc.Clipboard(
                        id="refresh-token-copy", 
                        title="Copy refresh token",
                        style={
                            'width': '120px',
                            'textAlign': 'center'
                        },
                        className="halberd-button"
                    ),
                ])
            ])
        ]),
        

        
    ]
    
    return dbc.Card(
        dbc.CardBody([
            html.H4([DashIconify(icon="mdi:key-chain", className="me-2"), "Access Token Information"], className="card-title mb-3"),
            *card_content
        ]),
        className="mb-3 bg-halberd-dark"
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
                className="mb-3 bg-halberd-dark"
            )
        )

    return info_output_div

def generate_gcp_access_info(credential_name):
    info_output_div = []

    if credential_name:
        try :
            manager = GCPAccess()
            manager.set_activate_credentials(credential_name)
            manager.get_current_access()
            # Helper function to create info row
            def create_info_row(icon, label, value, value_class=""):
                return html.Div([
                    DashIconify(icon=icon, className="me-2"),
                    html.Strong(label),
                    html.Span(value, className=f"ms-2 {value_class}")
                ], className="mb-3")

            # Helper function to create scopes info row with bullet points
            def create_scopes_info_row(icon, label, scopes, value_class=""):
                if isinstance(scopes, (list, tuple)):
                    scope_items = [html.Li(scope, className="mb-1") for scope in scopes]
                    scopes_display = html.Ul(scope_items, className="mb-0 ps-3", style={"listStyleType": "disc"})
                else:
                    scopes_display = html.Span(str(scopes), className=f"ms-2 {value_class}")
                
                return html.Div([
                    DashIconify(icon=icon, className="me-2"),
                    html.Strong(label),
                    html.Div(scopes_display, className="ms-2")
                ], className="mb-3")

            # Helper function to create GCP card
            def create_gcp_card(validity_status, validity_class, card_content, reasons: str=None):
                return dbc.Card(
                    dbc.CardBody([
                        html.H4([
                            DashIconify(icon="mdi:google-cloud", className="me-2"),
                            "Access: ",
                            html.Span(validity_status, className=validity_class)
                        ], className="card-title mb-3"),
                        html.Div(
                            html.Span(f"Reasons: {reasons}", className="text-muted"),
                            className="mb-3"
                        ) if reasons else "",
                        dbc.Row([dbc.Col(card_content, width=12)])
                    ]),
                    className="mb-3 bg-halberd-dark"
                )

            if manager.credential_type == "short_lived_token":
                expiration_state, _ = manager.get_expired_info()
                credential = manager.credential

                # Use the token as needed
                validity_status = "VALID SESSION" if not expiration_state else "CREDENTIAL EXPIRED OR INVALID"
                validity_class = "text-success" if not expiration_state else "text-warning"
                reasons = "" if not expiration_state else "Token is expired or invalid"
                
                card_content = [
                    create_info_row("mdi:account-key", "Name", credential_name, "text-info"),
                    create_info_row("mdi:account-key", "Credential Type", "Short-lived token", "text-info"),
                    create_scopes_info_row("mdi:telescope", "Scopes:", credential.scopes)
                ]
                
                info_output_div.append(create_gcp_card(validity_status, validity_class, card_content, reasons=reasons))
            else:
                reasons : str = None
                try:
                    expiration_state, _ = manager.get_expired_info()
                except Exception as e:
                    
                    if e.args[0] == "invalid_grant: Invalid JWT Signature.":
                        expiration_state = True
                        reasons = "Invalid JWT Signature"
                    elif e.args[0] == "Reauthentication is needed. Please run `gcloud auth application-default login` to reauthenticate.":
                        expiration_state = True
                        reasons = "Reauthentication is needed with `gcloud auth application-default login`"
                    else:
                        raise

                
                if expiration_state is False and manager.get_validation():
                    credential = manager.credential
                    service_account_email = getattr(credential, "service_account_email", None)
                    credential_type = (
                        "Service Account Private Key" if isinstance(credential, ServiceAccountCredentials)
                        else "Application Default Credential"
                    )
                    card_content = [
                        create_info_row("mdi:account-key", "Name", credential_name, "text-info"),
                        create_info_row("mdi:account-key", "Credential Type", credential_type, "text-info"),
                    ]
                    if service_account_email:
                        card_content.append(create_info_row("mdi:account-cash", "Email", service_account_email))
                    project_id = getattr(credential, "project_id", None)
                    if project_id:
                        card_content.append(create_info_row("ant-design:project-twotone", "Project:", project_id))
                    card_content.append(create_scopes_info_row("mdi:telescope", "Scopes:", credential.scopes))
                    info_output_div.append(create_gcp_card("VALID SESSION", "text-success", card_content))
                else:
                    credential = manager.credential
                    credential_type = (
                        "Service Account Private Key" if isinstance(credential, ServiceAccountCredentials)
                        else "Application Default Credential"
                    )
                    project_id = getattr(credential, "project_id", None)
                    card_content = [
                        create_info_row("mdi:account-key", "Name", credential_name, "text-info"),
                        create_info_row("mdi:account-key", "Credential Type", credential_type, "text-info"),
                    ]
                    if project_id:
                        card_content.append(create_info_row("ant-design:project-twotone", "Project:", project_id))
                    card_content.append(create_scopes_info_row("mdi:telescope", "Scopes:", credential.scopes))
                    info_output_div.append(create_gcp_card("CREDENTIAL EXPIRED OR INVALID", "text-warning", card_content, reasons=reasons))
        except Exception as e:
            info_output_div.append(
                dbc.Card(
                    dbc.CardBody([
                        html.H4([
                            DashIconify(icon="mdi:google-cloud", className="me-2"),
                            "Access: ",
                            html.Span(f"SYSTEM ERROR: {e}", className="text-danger")
                        ], className="card-title")
                    ]),
                    className="mb-3 bg-halberd-dark"
                )
            )
    else:
        info_output_div.append(
                dbc.Card(
                    dbc.CardBody([
                        html.H4([
                            DashIconify(icon="mdi:google-cloud", className="me-2"),
                            "Access: ",
                            html.Span("CREDENTIAL ARE NOT SET", className="text-danger")
                        ], className="card-title")
                    ]),
                    className="mb-3 bg-halberd-dark"
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
                    className="mb-3 bg-halberd-dark"
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
                    className="mb-3 bg-halberd-dark"
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
                className="mb-3 bg-halberd-dark"
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

def generate_remove_btn(id_attribute: dict):
    btn = dbc.Col([
        dbc.Button(
            html.I(className="fas fa-trash-alt"),
            id={"type": "remove-step-button", **id_attribute},
            color="link",
            className="text-danger p-0",
            title="Remove step"
        )
    ], width=2, className="text-end")
    return btn
