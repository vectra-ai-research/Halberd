'''
Page Navigation url : app/attack
Page Description : Configure and execute Halberd attack techniques and view technique response.
'''

import boto3
import uuid
import datetime
import time
import json

from dash import html, dcc, register_page, callback, ALL
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify

from attack_techniques.technique_registry import *

from core.Functions import generate_technique_info, GetAllPlaybooks, ParseTechniqueResponse, generate_attack_technique_options, generate_attack_tactics_options, generate_attack_technique_config, generate_entra_access_info, generate_aws_access_info, generate_azure_access_info, generate_gcp_access_info
from core.entra.entra_token_manager import EntraTokenManager
from core.logging.logger import app_logger,StructuredAppLog
from core.azure.azure_access import AzureAccess
from core.gcp.gcp_access import GCPAccess
from core.aws.aws_session_manager import SessionManager
from core.output_manager.output_manager import OutputManager
from core.playbook.playbook import Playbook
from core.playbook.playbook_step import PlaybookStep

# Register page to app       
register_page(__name__, path='/attack', name='Attack')

layout = html.Div([
    html.Div([
        dbc.Tabs(
            [
                dbc.Tab(label="Entra ID", tab_id="tab-attack-EntraID",label_class_name="halberd-brand-heading text-danger",
                ),
                dbc.Tab(
                    label="M365", tab_id="tab-attack-M365",label_class_name="halberd-brand-heading text-danger",
                ),
                dbc.Tab(
                    label="AWS", tab_id="tab-attack-AWS",label_class_name="halberd-brand-heading text-danger",
                ),
                    dbc.Tab(label="Azure", tab_id="tab-attack-Azure",label_class_name="halberd-brand-heading text-danger",
                ),
                    dbc.Tab(label="GCP", tab_id="tab-attack-GCP",label_class_name="halberd-brand-heading text-danger",
                ),
            ],
            id="attack-surface-tabs",
            active_tab="tab-attack-EntraID",
            class_name="mb-2 halberd-depth-card",
        )
    ]),
    html.Div([
        dbc.Row([
            # Column 1: Display technique selection options
            dbc.Col([
                # Attack surface tabs
                html.Div([
                    # Tactics dropdown
                    dcc.Dropdown(
                        id = "tactic-dropdown", 
                        className= "halberd-dropdown mb-4"
                    ),
                    # Div to display techniques list
                    html.Div(
                        id="attack-techniques-options-div"
                    )
                ], className= "bg-halberd-dark mx-3"),
            ],  md=3, className="bg-halberd-dark"),
            
            # Column 2 : Display technique information
            dbc.Col([
                html.Div(id="attack-technique-info-div")
            ],  md=4, className="bg-halberd-dark"),
            
            # Column 3 : Display technique configuration
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader(html.Div("Technique Configuration", className="mb-0 halberd-brand text-2xl")),
                    dbc.CardBody(id="attack-config-div")
                ], className="mb-3 halberd-depth-card"),
                # html.Div(id="attack-config-div", className="p-4 halberd-depth-card")
            ], md=5, className="bg-halberd-dark"),    
        ]),
    ], style={"justify-content": "center", "align-items": "center"},
    className="mb-3"
    ),
    
    # Display technique output
    dcc.Store(id="technique-output-memory-store"),
    dbc.Col([
        dbc.Row(
            [
                dbc.Col(
                    html.H4("Response", className="halberd-brand")
                ),
                dbc.Col(
                    html.A(
                        dbc.Button(
                            [
                                DashIconify(
                                    icon="mdi:history",
                                    width=20,
                                    className="me-2"
                                ),
                                "Attack History"
                            ],
                            n_clicks=0,
                            className="ms-2 halberd-button-secondary",
                            id="history-button",
                        ),
                        href="/attack-history", 
                        target="_blank", 
                        style={'float': 'right', 'margin-left': '10px'},
                        className= "halberd-text"
                    )
                )
            ],
            className= "mb-2"
        ),
        dbc.Row(
            [
                dbc.Col(
                    dcc.Loading(
                        id="attack-output-loading",
                        type="default",
                        children=html.Div(
                            [
                                dbc.Col([
                                    dbc.Row(
                                        DashIconify(
                                            icon="mdi:information-outline", #Information icon
                                            width=48,
                                            height=48,
                                            className="text-muted mb-3 me-3"
                                        ),
                                    ),
                                    dbc.Row(
                                        html.P("Execute Technique to View Response") # Default message when no technique is executed
                                    )
                                ], 
                                className="halberd-text text-muted",
                                style={
                                    'textAlign': 'center',
                                    'height': '35vh',
                                    'display': 'flex',
                                    'alignItems': 'center',
                                    'justifyContent': 'center',
                                })
                            ],
                            id= "execution-output-div", 
                            style={
                                "height":"40vh", 
                                "overflowY": "auto", 
                                "border":"1px solid #ccc", 
                                "padding-right": "10px", 
                                "padding-left": "10px", 
                                "padding-top": "10px", 
                                "padding-bottom": "10px"
                            },
                            className="halberd-text"
                        )
                    )
                )
            ]
        )
    ]),
    
    # Access details modal
    dbc.Modal(
        [
            dbc.ModalHeader(dbc.ModalTitle("Access Manager", className="halberd-brand")),
            dbc.ModalBody(id = "attack-access-info-display-modal-body")
        ],
        id="attack-access-info-display-modal",
        size="xl",
        scrollable=True,
        backdrop="static"
    ),
],
className="bg-halberd-dark halberd-text",
style={
    'minHeight': '100vh',
    "padding-right": "20px", 
    "padding-left": "20px"
    }
)

# Callbacks
'''Callback to generate tactic dropdown options in Attack view'''
@callback(
        Output(component_id = "tactic-dropdown", component_property = "options"), 
        Output(component_id = "tactic-dropdown", component_property = "value"), 
        Input(component_id = "attack-surface-tabs", component_property = "active_tab")
)
def generate_tactic_dropdown_callback(tab):
    tactic_dropdown_option = generate_attack_tactics_options(tab)
    return tactic_dropdown_option, tactic_dropdown_option[0]["value"]

'''Callback to generate techniques radio options in Attack page'''
@callback(
        Output(component_id = "attack-techniques-options-div", component_property = "children"), 
        Input(component_id = "attack-surface-tabs", component_property = "active_tab"),
        Input(component_id = "tactic-dropdown", component_property = "value")
)
def generate_attack_technique_options_callback(tab, tactic):
    technique_options = generate_attack_technique_options(tab, tactic)
    return technique_options


'''Callback to display technique config'''
@callback(
        Output(component_id = "attack-config-div", component_property = "children"), 
        Input(component_id = "attack-options-radio", component_property = "value"),
        prevent_initial_call=True
)
def display_attack_technique_config_callback(technique):
    technique_config = generate_attack_technique_config(technique)
    return technique_config

'''Callback to execute a technqiue'''
@callback(
        Output(component_id = "execution-output-div", component_property = "children"), 
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True),
        Input(component_id= "technique-execute-button", component_property= "n_clicks"), 
        State(component_id = "tactic-dropdown", component_property = "value"),
        State(component_id = "attack-options-radio", component_property = "value"), 
        State({"type": "technique-config-display", "index": ALL}, "value"), 
        State({"type": "technique-config-display-boolean-switch", "index": ALL}, "on"), 
        State({"type": "technique-config-display-file-upload", "index": ALL}, "contents"), 
        prevent_initial_call = True
)
def execute_technique_callback(n_clicks, tactic, t_id, values, bool_on, file_content):
    '''The input callback can handle text inputs, boolean flags and file upload content'''
    if n_clicks == 0:
        raise PreventUpdate
    
    technique = TechniqueRegistry.get_technique(t_id)
    technique_params = (technique().get_parameters())

    # Technique attack surface / category
    attack_surface = TechniqueRegistry.get_technique_category(t_id)
    # Active entity / Source
    active_entity = "Unknown"

    if attack_surface in ["m365","entra_id"]:
        manager = EntraTokenManager()
        access_token = manager.get_active_token()
        
        if access_token:
            try:
                access_info = manager.decode_jwt_token(access_token)
                active_entity = access_info['Entity']
            except Exception as e:
                active_entity = "Unknown"
        else: 
            active_entity = "Unknown"
    
    if attack_surface == "aws":
        try:
            manager = SessionManager()
            # set default session
            sts_client = boto3.client('sts')
            session_info = sts_client.get_caller_identity()
            active_entity = session_info['UserId']
        except:
            active_entity = "Unknown"

    if attack_surface == "azure":
        try:
            current_access = AzureAccess().get_current_subscription_info()
            active_entity = current_access['user']['name']
        except:
            active_entity = "Unknown"

    if attack_surface == "gcp":
        try:
            current_access = None
            if t_id == "GCPEstablishAccessAsServiceAccount":
                manager = GCPAccess(raw_credentials=file_content[0],name=values[0])
                current_access = manager.get_current_access().get("name")
                current_access = manager.get_detailed_credential(name=current_access)
            else:
                manager = GCPAccess()
                current_access = manager.get_current_access()
            if current_access["credential"]["type"] == "service_account":
                active_entity = current_access["credential"]["client_email"]
            if current_access["credential"]["type"] == "user_authorized":
                active_entity = current_access["credential"]["client_id"]

        except:
            active_entity = "Unknown"
        

    # Create technique input
    technique_input = {}
    file_input = {}
    bool_input = {}
    i=0
    for param in technique_params:
        if technique_params[param]['input_field_type'] not in ["bool", "upload"]: 
            technique_input[param] = [*values][i]
            i+=1
        elif technique_params[param]['input_field_type'] == "upload":
            file_input[param] = technique_params[param]
        elif technique_params[param]['input_field_type'] == "bool":
            bool_input[param] = technique_params[param]
    
    if file_content:
        i = 0
        for param in file_input:
            technique_input[param] = [*file_content][i]
            i+=1

    if bool_on:
        i = 0
        for param in bool_input:
            technique_input[param] = [*bool_on][i]
            i+=1

    # Log technique execution start
    event_id = str(uuid.uuid4()) #Generate unique event_id for the execution
    
    app_logger.info(StructuredAppLog("Technique Execution",
        event_id = event_id,
        source = active_entity,
        status = "started",
        technique = t_id,
        tactic=tactic,
        timestamp=datetime.datetime.now().isoformat())
    )

    # Execute technique    
    output = technique().execute(**technique_input)
    
    # check if technique output is in the expected tuple format (success, response)
    if isinstance(output, tuple) and len(output) == 2:
        result, response = output

        # Initialize output manager
        output_manager = OutputManager()

        if result.value == "success":
            # Log technique execution success
            app_logger.info(StructuredAppLog("Technique Execution",
                event_id = event_id,
                source = active_entity,
                status = "completed",
                result = "success",
                technique = t_id,
                target = None,
                tactic=tactic,
                timestamp=datetime.datetime.now().isoformat())
            )

            # Save output to file
            output_manager.store_technique_output(
                data=response['value'], 
                technique_name=t_id, 
                event_id=event_id
            )

            # Return results
            return ParseTechniqueResponse(response['value']), True, "Technique Execution Successful"
        
        # Log technique execution failure
        app_logger.info(StructuredAppLog("Technique Execution",
            event_id = event_id,
            source = active_entity,
            status = "completed",
            result = "failed",
            technique = t_id,
            target = None,
            tactic=tactic,
            timestamp=datetime.datetime.now().isoformat())
        )
        # Save output to file
        output_manager.store_technique_output(
            data=response['error'], 
            technique_name=t_id, 
            event_id=event_id
        )
        # Return results
        return ParseTechniqueResponse(response['error']), True, "Technique Execution Failed"
    
    # Unexpected technique output
    return ParseTechniqueResponse(""), True, "Technique Execution Failed"

'''Callback to display selected technique info in Attack view'''
@callback(
        Output(component_id = "attack-technique-info-div", component_property = "children", allow_duplicate=True),
        Input(component_id = "attack-options-radio", component_property = "value"), 
        prevent_initial_call=True
)
def display_attack_technique_info_callback(t_id):
    if t_id is None:
        raise PreventUpdate
    
    # Get technique details
    technique_details = generate_technique_info(t_id)
    
    return technique_details

'''Callback to set AWS active/default session and populate AWS access info dynamically based on selected session'''
@callback(
        Output(component_id = "aws-access-info-div", component_property = "children"), 
        Input(component_id = "interval-to-trigger-initialization-check", component_property = "n_intervals"), 
        Input(component_id = "aws-session-selector-dropdown", component_property = "value"))
def generate_aws_access_info_callback(n_interval, session_name):
    return generate_aws_access_info(session_name)

'''Callback to populate EntraID access info'''
@callback(
        Output(component_id = "access-info-div", component_property = "children"), 
        Input(component_id = "interval-to-trigger-initialization-check", component_property = "n_intervals"))
def generate_entra_access_info_callback(n_intervals):
    return generate_entra_access_info("active")

'''Callback to set active Entra ID access token'''
@callback(
        Output(component_id = "access-info-div", component_property = "children",  allow_duplicate=True), 
        Input(component_id = "token-selector-dropdown", component_property = "value"), 
        prevent_initial_call=True)
def set_entra_active_token_callback(value):

    manager = EntraTokenManager()

    # Retrieve the actual token from tokens file
    selected_token = json.loads(value)
    selected_token_entity = list(selected_token.keys())[0]
    selected_token_exp = list(selected_token.values())[0]

    for token in manager.get_all_tokens():
        token_info = manager.decode_jwt_token(token)
        if token_info != None:
            if token_info['Entity'] == selected_token_entity and token_info['Access Exp'] == selected_token_exp:
                access_token = token
                break
        else:
            pass
    
    # Set selected token as active
    manager.set_active_token(access_token)

    # Update access info div with selected token info
    return generate_entra_access_info(access_token=access_token)

'''Callback to generate Entra ID token options in Access dropdown'''
@callback(
        Output(component_id = "token-selector-dropdown", component_property = "options"), 
        Input(component_id = "token-selector-dropdown", component_property = "title"))
def generate_entra_token_dropdown_callback(title):
    manager = EntraTokenManager()
    if title == None:
        all_tokens = []
        for token in manager.get_all_tokens():
            token_info = manager.decode_jwt_token(token)
            if token_info != None:
                selected_value = {token_info.get('Entity') : token_info.get('Access Exp')}
                all_tokens.append(
                    {
                        'label': html.Div(f"{token_info['Entity']}-{token_info.get('Access Exp')}", className="halberd-text"), 
                        'value': json.dumps(selected_value)
                    }
                )

        return all_tokens
    
'''Callback to populate Azure access info dynamically based on selected subscription'''
@callback(
        Output(component_id = "azure-access-info-div", component_property = "children"), 
        Input(component_id = "interval-to-trigger-initialization-check", component_property = "n_intervals"), 
        Input(component_id = "azure-subscription-selector-dropdown", component_property = "value"))
def generate_azure_access_info_callback(n_intervals, value):
    return generate_azure_access_info(value)

'''Callback to generate Azure subscription options in Access dropdown'''
@callback(
        Output(component_id = "azure-subscription-selector-dropdown", component_property = "options"), 
        Input(component_id = "azure-subscription-selector-dropdown", component_property = "title"))
def generate_azure_sub_dropdown_callback(title):
    if title == None:
        all_subscriptions = []
        
        for subs in AzureAccess().get_account_available_subscriptions():
            selected_value = subs.get("id")
            all_subscriptions.append(
                {
                    'label': html.Div(subs.get("name"), className="halberd-text"), 
                    'value': selected_value
                }
            )

        return all_subscriptions
    
'''Callback to add technique as step to playbook'''
@callback(
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), 
        Output(component_id = "app-error-display-modal", component_property = "is_open", allow_duplicate=True),
        Output(component_id = "app-error-display-modal-body", component_property = "children", allow_duplicate=True),
        Input(component_id = "confirm-add-to-playbook-modal-button", component_property = "n_clicks"), 
        Input(component_id = "att-pb-selector-dropdown", component_property = "value"), 
        State(component_id = "pb-add-step-number-input", component_property = "value"),
        State(component_id = "pb-add-step-wait-input", component_property = "value"),
        State(component_id = "attack-options-radio", component_property = "value"),
        State(component_id = {"type": "technique-config-display", "index": ALL}, component_property = "value"), 
        State(component_id = {"type": "technique-config-display-boolean-switch", "index": ALL}, component_property = "on"), 
        State(component_id = {"type": "technique-config-display-file-upload", "index": ALL}, component_property = "contents"),
        prevent_initial_call=True
    )
def add_technique_to_pb_callback(n_clicks, selected_pb, step_no, wait, t_id, values, bool_on, file_content):
    if n_clicks == 0:
        raise PreventUpdate
    
    # If config has file as input
    if selected_pb:
        if file_content:
            for pb in GetAllPlaybooks():
                pb_config = Playbook(pb)
                if  pb_config.name == selected_pb:
                    break

            technique_input.append(file_content)
        
        else:
            for pb in GetAllPlaybooks():
                pb_config = Playbook(pb)
                if  pb_config.name == selected_pb:
                    break
        
        # Create technique input
        technique = TechniqueRegistry.get_technique(t_id)
        technique_params = (technique().get_parameters())

        technique_input = {}
        file_input = {}
        bool_input = {}
        i=0
        for param in technique_params:
            if technique_params[param]['input_field_type'] not in ["bool", "upload"]: 
                technique_input[param] = [*values][i]
                i+=1
            elif technique_params[param]['input_field_type'] == "upload":
                file_input[param] = technique_params[param]
            elif technique_params[param]['input_field_type'] == "bool":
                bool_input[param] = technique_params[param]
        
        if file_content:
            i = 0
            for param in file_input:
                technique_input[param] = [*file_content][i]
                i+=1

        if bool_on:
            i = 0
            for param in bool_input:
                technique_input[param] = [*bool_on][i]
                i+=1

        # Create playbook step
        try:
            new_step = PlaybookStep(module=t_id, params=technique_input, wait=wait)
            
            # Add technique to playbook
            pb_config.add_step(new_step=new_step, step_no=step_no)
            
            # Save and update with new playbook config
            pb_config.save()

            return True, "Added to Playbook", False, ""
        except Exception as e:
            # Display error in error pop-up
            return False, "", True, str(e)
    else:
        # Display error in error pop-up
        return False, "", True, "Cannot Add Step : No Playbook Selected"

'''Callback to generate AWS session options in AWS sessions dropdown'''
@callback(
    Output(component_id = "aws-session-selector-dropdown", component_property = "options"), 
    Input(component_id = "aws-session-selector-dropdown", component_property = "title")
)
def generate_aws_session_options_dropdown_callback(session_name):
    manager = SessionManager()
    if session_name == None:
        all_sessions = []
        for session in manager.list_sessions():
            all_sessions.append(
                {
                    'label': html.Div(session['session_name'], className="halberd-text"), 
                    'value': session['session_name']
                }
            )

        return all_sessions

'''Callback to generate GCP session options in GCP sessions dropdown'''
@callback(
    Output(component_id = "gcp-credential-selector-dropdown", component_property = "options"), 
    Input(component_id = "gcp-credential-selector-dropdown", component_property = "title")
)
def generate_gcp_credential_options_dropdown_callback(credential_name):
    manager = GCPAccess()
    if credential_name == None:
        all_sessions = []
        for credential in manager.list_credentials():
            all_sessions.append(
                {
                    'label': html.Div(credential['name'], className="halberd-text"), 
                    'value': credential['name']
                }
            )
        return all_sessions
    
'''Callback to set GCP active credential and populate GCP access info dynamically based on selected credential'''
@callback(
        Output(component_id = "gcp-access-info-div", component_property = "children"), 
        Input(component_id = "interval-to-trigger-initialization-check", component_property = "n_intervals"), 
        Input(component_id = "gcp-credential-selector-dropdown", component_property = "value"))
def generate_gcp_access_info_callback(n_interval, value):
    if value == None :
        try : 
            value = GCPAccess().get_current_access().get("name")
        except:
            pass
    return generate_gcp_access_info(value)

'''Callback to delete EntraID access token'''
@callback(
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True),
        State(component_id = "token-selector-dropdown", component_property = "value"),
        Input(component_id = "del-entra-token-button", component_property = "n_clicks"),
        prevent_initial_call=True
    )
def delete_entra_token_callback(value, n_clicks):
    if n_clicks is None or value is None:
        raise PreventUpdate
    
    # EntraID token manager
    manager = EntraTokenManager()

    # Load the selected token and get token info
    selected_token = json.loads(value)
    selected_token_entity = list(selected_token.keys())[0]
    selected_token_exp = list(selected_token.values())[0]

    # Check token in token list
    for token in manager.get_all_tokens():
        token_info = manager.decode_jwt_token(token)
        if token_info != None:
            if token_info['Entity'] == selected_token_entity and token_info['Access Exp'] == selected_token_exp:
                access_token = token
                break
        else:
            pass
    
    # Delete selected token
    manager.delete_token(access_token)
    return True, "EntraID Token Deleted"

'''Callback to delete AWS session'''
@callback(
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True),
        State(component_id = "aws-session-selector-dropdown", component_property = "value"),
        Input(component_id = "del-aws-session-button", component_property = "n_clicks"),
        prevent_initial_call=True
    )
def delete_aws_session_callback(session_name, n_clicks):
    if n_clicks is None or session_name is None:
        raise PreventUpdate
    
    # AWS session manager
    manager = SessionManager()
    # Delete selected session
    manager.remove_session(session_name)

    return True, "AWS Session Deleted"

'''Callback to delete Azure session'''
@callback(
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True),
        Input(component_id = "del-az-session-button", component_property = "n_clicks"),
        prevent_initial_call=True
    )
def delete_azure_session_callback(n_clicks):
    if n_clicks is None:
        raise PreventUpdate
    
    # Azure access manager
    manager = AzureAccess()
    # Logout selected session
    logout = manager.logout()
    if logout:
        return True, "Azure Session Closed"
    
'''Callback to delete GCP credential'''
@callback(
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True),
        State(component_id = "gcp-credential-selector-dropdown", component_property = "value"),
        Input(component_id = "del-gcp-credential-button", component_property = "n_clicks"),
        prevent_initial_call=True
    )
def delete_gcp_credential_callback(credential_name, n_clicks):
    if n_clicks is None:
        raise PreventUpdate
    
    # GCP session manager
    manager = GCPAccess()
    
    if credential_name is None:
        credential_name = manager.get_current_access().get("name") 
    
    # Delete selected session
    manager.delete_current_credentials()

    return True, "GCP Credential Deleted"

'''Callback to display access info button dynamically'''
@callback(
    Output(component_id = "attack-access-info-dynamic-btn", component_property = "children"),
    Output(component_id = "attack-access-info-dynamic-btn", component_property = "color"),
    Input(component_id = "attack-surface-tabs", component_property = "active_tab"),
    Input(component_id="attack-access-info-display-modal", component_property="is_open") # refresh button status automatically
)
def update_access_button_callback(active_tab, is_open):
    if active_tab is None:
        return "No Access", "danger"
    
    if active_tab in ["tab-attack-EntraID", "tab-attack-M365"]:
        manager = EntraTokenManager()
        access_token = manager.get_active_token()
        # Check if tokens available
        if access_token:
        # Check if token valid
            access_info = manager.decode_jwt_token(access_token)
            if access_info != None:
                if access_info['Access Exp'] < datetime.datetime.fromtimestamp(int(time.time()), tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'):
                    return "Access Expired", "danger"
                else:
                    return access_info['Entity'], "success"
        else: 
            # No valid token
            return "No EntraID / M365 Access", "danger"
        
    elif active_tab == "tab-attack-AWS":
        try:
            aws_manager = SessionManager()
            active_aws_session = aws_manager.get_active_session()
            if active_aws_session:
                user = aws_manager.get_user_details()
                user_id = user['user_id']

                return user_id, "success"
            else:
                return "No AWS Access", "danger"
        except:
            return "No AWS Access", "danger"
    elif active_tab == "tab-attack-Azure":
        current_access = AzureAccess().get_current_subscription_info()
        try:
            if current_access != None:
                user = current_access.get("user").get("name")
                subscription = current_access.get("name")
                return f"{user} [{subscription}]", "success"
            else:
                return "No Access", "danger"
        except:
            return "No Azure Access", "danger"
    elif active_tab == "tab-attack-GCP":
        gcp_manager = GCPAccess()
        try :
            user = gcp_manager.get_current_access().get("name")
            if user != None:
                return user, "success"
            else:
                return "No Access", "danger"
        except :
            return "No Access", "danger"

'''Callback to display access info in modal'''
@callback(
        Output("attack-access-info-display-modal", "is_open", allow_duplicate=True),
        Output("attack-access-info-display-modal-body", "children", allow_duplicate = True),
        Input(component_id = "attack-access-info-dynamic-btn", component_property = "n_clicks"),
        State(component_id = "attack-surface-tabs", component_property = "active_tab"),
        prevent_initial_call=True
)
def display_access_info_in_modal_callback(n_clicks, active_tab):
    if n_clicks is None:
        raise PreventUpdate
    
    def create_access_section(dropdown_id, remove_button_id, info_div_id):
        """Dynamically creates access info sections on Access page"""
        return html.Div(
            [
                dbc.Row([
                    dbc.Col(
                        html.H4("Set Access"),   
                        md=2
                    ),
                    dbc.Col(
                        dcc.Dropdown(id=dropdown_id, className="halberd-dropdown halberd-text"),
                        md=8
                    ),
                    dbc.Col(
                        dbc.Button("Remove Access", id=remove_button_id, color="danger", size="sm", className="halberd-button"),
                        md=2
                    )
                ], className="mt-2 mb-3"),
                dcc.Loading(
                    id=f"{info_div_id}-loading",
                    type="default",
                    children=html.Div(id=info_div_id, className="halberd-depth-card")
                ),
                
            ],className="halberd-text")
            
    if active_tab in ["tab-attack-EntraID", "tab-attack-M365"]:    
        return True, create_access_section(
            "token-selector-dropdown",
            "del-entra-token-button",
            "access-info-div"
        )
    elif active_tab == "tab-attack-AWS":    
        return True, create_access_section(
            "aws-session-selector-dropdown",
            "del-aws-session-button",
            "aws-access-info-div"
        )
    elif active_tab == "tab-attack-Azure":    
        return True, create_access_section(
            "azure-subscription-selector-dropdown",
            "del-az-session-button",
            "azure-access-info-div"
        )
    elif active_tab == "tab-attack-GCP":    
        return True, create_access_section(
            "gcp-credential-selector-dropdown",
            "del-gcp-credential-button",
            "gcp-access-info-div"
        )