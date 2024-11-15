#!/usr/bin/env python3
import json
import dash
import datetime
import time
import os
import boto3
import uuid
import threading
import dash_bootstrap_components as dbc
from dash import dcc, html, ALL, callback_context, no_update, MATCH, ctx
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
import dash_daq as daq
from dash_iconify import DashIconify
import pandas as pd
from core.entra.entra_token_manager import EntraTokenManager
from core.azure.azure_access import AzureAccess
from core.gcp.gcp_access import GCPAccess
from pages.dashboard.entity_map import GenerateEntityMappingGraph
from core.Functions import generate_technique_info, run_initialization_check, AddNewSchedule, GetAllPlaybooks, ParseTechniqueResponse, playbook_viz_generator, generate_attack_technique_options, generate_attack_tactics_options, generate_attack_technique_config, generate_entra_access_info, generate_aws_access_info, generate_azure_access_info, parse_app_log_file, group_app_log_events, create_app_log_event_summary, get_playbook_stats, parse_execution_report
from core.playbook.playbook import Playbook
from core.playbook.playbook_step import PlaybookStep
from core.playbook.playbook_error import PlaybookError
from core.Constants import *
from core.aws.aws_session_manager import SessionManager
from attack_techniques.technique_registry import *
from core.logging.logger import setup_logger,StructuredAppLog
from core.logging.report import read_log_file, analyze_log, generate_html_report
from core.output_manager.output_manager import OutputManager
from pages.attack_analyse import process_attack_data, create_metric_card, create_df_from_attack_logs, create_bar_chart, create_pie_chart, create_timeline_graph
from pages.automator import create_playbook_item, create_playbook_manager_layout, schedule_pb_div, export_pb_div, generate_playbook_creator_offcanvas, generate_step_form, playbook_editor_create_parameter_inputs, create_step_progress_card

# Create Application
app = dash.Dash(__name__,  external_stylesheets=[dbc.themes.LUX, dbc.icons.BOOTSTRAP],title='Halberd', update_title='Loading...', suppress_callback_exceptions=True)

# Navigation bar layout
navbar = dbc.NavbarSimple(
    id = "halberd-main-navbar",
    children=[
        dbc.NavItem(dbc.NavLink("Attack", href="/attack")),
        dbc.NavItem(dbc.NavLink("Recon", href="/recon")),
        dbc.NavItem(dbc.NavLink("Automator", href="/automator")),
        dbc.NavItem(dbc.NavLink("Analyse", href="/attack-analyse"))
    ],
    brand= html.Div([
        dbc.Row(
                [
                    dbc.Col(html.Img(src="/assets/favicon.ico", height="30px")),
                    dbc.Col(html.Div("Halberd", className="text-danger", style={'font-family':'horizon'})),
                ],
            ),
        ]),
    brand_href="/home",
    color="dark",
    dark=True,
    sticky= "top",
)

# App layout
app.layout = html.Div([
    dcc.Interval(id='interval-to-trigger-initialization-check',interval=60000,n_intervals=0),
    html.Div(id='hidden-div', style={'display':'none'}),
    dcc.Location(id='url', refresh=False),
    navbar,
    html.Div(id='page-content',className="bg-dark", style={'overflow': 'auto'}),
    dbc.Toast(
        children = "Hello!",
        id="app-welcome-notification",
        header="Welcome to Halberd",
        is_open=True,
        dismissable=True,
        duration=3000,
        color="primary",
        style={"position": "fixed", "top": 92, "right": 10, "width": 350},
    ),
    dbc.Toast(
        children = "",
        id="app-notification",
        header="Notification",
        is_open=False,
        dismissable=True,
        duration=5000,
        color="primary",
        style={"position": "fixed", "top": 92, "right": 10, "width": 350},
    ),
    dcc.Download(id="app-download-sink"),
    dbc.Modal(
        [
            dbc.ModalHeader(dbc.ModalTitle("Technique Details")),
            dbc.ModalBody(id = "app-technique-info-display-modal-body"),
            dbc.ModalFooter(
                dbc.Button("Close", id="close-app-technique-info-display-modal", className="ml-auto")
            ),
        ],
        id="app-technique-info-display-modal",
        size="lg",
        scrollable=True,
    ),
    # Error modal -> use this to display an error pop up message
    dbc.Modal(
    [
        dbc.ModalHeader("Error", style={"background-color": "#dc3545", "color": "white"}),
        dbc.ModalBody(id="app-error-display-modal-body"),
        dbc.ModalFooter(
            dbc.Button("Close", id="close-app-error-display-modal", className="ml-auto")
        ),
    ],
    id="app-error-display-modal",
    is_open=False,
    ),
    # Success modal -> use this to display a success pop up message
    dbc.Modal(
    [
        dbc.ModalHeader("Success", style={"background-color": "#28a745", "color": "white"}),
        dbc.ModalBody(id="app-success-display-modal-body"),
        dbc.ModalFooter(
            dbc.Button("Close", id="close-app-success-display-modal", className="ml-auto")
        ),
    ],
    id="app-success-display-modal",
    is_open=False,
)
])

'''C001 - Callback to update the page content based on the URL'''
@app.callback(Output('page-content', 'children'), [Input('url', 'pathname')])
def display_page_from_url_callback(pathname):
    if pathname == '/home':
        from pages.home import page_layout
        return page_layout
    elif pathname == '/attack':
        from pages.attack import page_layout
        return page_layout
    elif pathname == '/recon':
        from pages.recon import page_layout
        return page_layout
    elif pathname == '/automator':
        return create_playbook_manager_layout()
    elif pathname == '/schedules':
        from pages.schedules import generate_automator_schedules_view
        return generate_automator_schedules_view()
    elif pathname == '/attack-history':
        from pages.attack_history import generate_attack_history_page
        return generate_attack_history_page()
    elif pathname == '/attack-analyse':
        from pages.attack_analyse import create_layout
        return create_layout()
    else:
        from pages.home import page_layout
        return page_layout

'''C002 - Callback to generate tactic dropdown options in Attack view'''
@app.callback(
        Output(component_id = "tactic-dropdown", component_property = "options"), 
        Output(component_id = "tactic-dropdown", component_property = "value"), 
        Input(component_id = "attack-surface-tabs", component_property = "active_tab")
)
def generate_tactic_dropdown_callback(tab):
    tactic_dropdown_option = generate_attack_tactics_options(tab)
    return tactic_dropdown_option, tactic_dropdown_option[0]["value"]

'''C003 - Callback to generate techniques radio options in Attack page'''
@app.callback(
        Output(component_id = "attack-techniques-options-div", component_property = "children"), 
        Input(component_id = "attack-surface-tabs", component_property = "active_tab"),
        Input(component_id = "tactic-dropdown", component_property = "value")
)
def generate_attack_technique_options_callback(tab, tactic):
    technique_options = generate_attack_technique_options(tab, tactic)
    return technique_options

'''C004 - Callback to display technique config'''
@app.callback(
        Output(component_id = "attack-config-div", component_property = "children"), 
        Input(component_id = "attack-options-radio", component_property = "value"),
        prevent_initial_call=True
)
def display_attack_technique_config_callback(technique):
    technique_config = generate_attack_technique_config(technique)
    return technique_config

'''C005 - Callback to execute a technqiue'''
@app.callback(
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
            current_access = GCPAccess().current_credentials()
            active_entity = current_access.service_account_email


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
    
    logger.info(StructuredAppLog("Technique Execution",
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
            logger.info(StructuredAppLog("Technique Execution",
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
        logger.info(StructuredAppLog("Technique Execution",
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
    
'''C006 - Entity Map - Generate Map'''
@app.callback(
    Output(component_id = "entity-map-display-div", component_property = "children", allow_duplicate=True),
    Input(component_id = "generate-entity-map-button", component_property = "n_clicks"),
    Input(component_id = "map-layout-select", component_property = "value"),
    Input(component_id = "filter-select", component_property = "value"),
    prevent_initial_call=True
)
def update_entity_map(n_clicks, map_layout, filter_category):
    if not n_clicks:
        return html.Div("Click 'Generate Entity Map' to view the map.")
    
    if filter_category == 'all':
        filter_category = None 

    return GenerateEntityMappingGraph(map_layout, filter_category)

'''C007 - Callback to display selected technique info in Attack view'''
@app.callback(
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

'''C008 - Callback to generate trace report'''
@app.callback(
    Output(component_id = "app-download-sink", component_property = "data", allow_duplicate=True),
    Input(component_id= "download-halberd-report-button", component_property= "n_clicks"),
    prevent_initial_call = True
)
def generate_trace_report_callback(n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    try:
        log_lines = read_log_file(APP_LOG_FILE)
        analysis_results = analyze_log(log_lines)
        html_report = generate_html_report(analysis_results)
        
        # Save the HTML report
        with open(f'{REPORT_DIR}/halberd_security_report.html', 'w', encoding='utf-8') as report_file:
            report_file.write(html_report)
        return dcc.send_file(f'{REPORT_DIR}/halberd_security_report.html')
    except FileNotFoundError:
        return (f"Error: The file '{APP_LOG_FILE}' was not found. Ensure the log file exists and the path is correct.")
    except Exception:
        raise PreventUpdate

'''C009 - Callback to download trace logs'''
@app.callback(
    Output("app-download-sink", "data"),
    Input("download-trace-logs-button", "n_clicks"),
    prevent_initial_call=True,
)
def download_trace_logs_callback(n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    # Parse log file and create summary
    events = parse_app_log_file(APP_LOG_FILE)
    grouped_events = group_app_log_events(events)
    summary = create_app_log_event_summary(grouped_events)

    # Create DataFrame
    df = pd.DataFrame(summary)
    return dcc.send_data_frame(df.to_csv, "attack_trace.csv", index=False)

'''C010 - Callback to set AWS active/default session and populate AWS access info dynamically based on selected session'''
@app.callback(
        Output(component_id = "aws-access-info-div", component_property = "children"), 
        Input(component_id = "interval-to-trigger-initialization-check", component_property = "n_intervals"), 
        Input(component_id = "aws-session-selector-dropdown", component_property = "value"))
def generate_aws_access_info_callback(n_interval, session_name):
    return generate_aws_access_info(session_name)

'''C011 - Callback to populate EntraID access info'''
@app.callback(
        Output(component_id = "access-info-div", component_property = "children"), 
        Input(component_id = "interval-to-trigger-initialization-check", component_property = "n_intervals"))
def generate_entra_access_info_callback(n_intervals):
    return generate_entra_access_info("active")

'''C012 - Callback to set active Entra ID access token'''
@app.callback(
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

'''C013 - Callback to generate Entra ID token options in Access dropdown'''
@app.callback(
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
                        'label': html.Div(f"{token_info['Entity']}-{token_info.get('Access Exp')}", className="text-dark"), 'value': json.dumps(selected_value)
                    }
                )

        return all_tokens

'''C014 - Recon page tab switcher'''
@app.callback(
        Output("recon-content-div", "children"), 
        Input("recon-target-tabs", "active_tab"))
def generate_content_from_recon_tab_callback(tab):
    if tab == "tab-recon-entity-map":
        from pages.dashboard.entity_map import page_layout
        return page_layout
    if tab == "tab-recon-roles":
        from pages.dashboard.recon_roles import page_layout
        return page_layout
    if tab == "tab-recon-users":
        from pages.dashboard.recon_users import page_layout
        return page_layout
    else:
        from pages.dashboard.entity_map import page_layout
        return page_layout

'''C015 - Callback to generate data in role recon dashboard'''
@app.callback(
        Output(component_id = "role-name-recon-div", component_property = "children"), 
        Output(component_id = "role-template-id-recon-div", component_property = "children"), 
        Output(component_id = "role-id-recon-div", component_property = "children"), 
        Output(component_id = "role-member-count-recon-div", component_property = "children"), 
        Output(component_id = "role-member-recon-div", component_property = "children"), 
        Output(component_id = "role-description-recon-div", component_property = "children"), 
        Input(component_id= "role-recon-start-button", component_property= "n_clicks"),
        Input(component_id = "role-recon-input", component_property = "value"))
def execute_recon_callback(n_clicks, role_name):
    if n_clicks == 0:
        raise PreventUpdate
    
    # Input validation
    if role_name in ["",None]:
        response = "N/A"
        return response, response, response, response, response, response
    
    # Import recon functions
    from pages.dashboard.recon_roles import FindRole, ReconRoleMembers
    
    # Execute recon
    role_name, role_id, role_template_id, role_description = FindRole(role_name)
    member_count, role_members = ReconRoleMembers(role_template_id)

    return role_name, role_template_id, role_id, member_count, role_members, role_description

'''C016 - Callback to generate data in user recon dashboard'''
@app.callback(Output(
    component_id = "user-displayname-recon-div", component_property = "children"), 
    Output(component_id = "user-id-recon-div", component_property = "children"), 
    Output(component_id = "user-upn-recon-div", component_property = "children"), 
    Output(component_id = "user-mail-recon-div", component_property = "children"), 
    Output(component_id = "user-job-title-recon-div", component_property = "children"), 
    Output(component_id = "user-location-recon-div", component_property = "children"), 
    Output(component_id = "user-phone-recon-div", component_property = "children"), 
    Output(component_id = "user-group-count-recon-div", component_property = "children"), 
    Output(component_id = "user-role-count-recon-div", component_property = "children"), 
    Output(component_id = "user-groups-recon-div", component_property = "children"), 
    Output(component_id = "user-roles-recon-div", component_property = "children"), 
    Output(component_id = "user-app-count-recon-div", component_property = "children"), 
    Output(component_id = "user-app-recon-div", component_property = "children"), 
    Input(component_id= "user-recon-start-button", component_property= "n_clicks"),
    Input(component_id = "user-recon-input", component_property = "value"))
def execute_user_recon_dashboard_callback(n_clicks, user_string):
    if n_clicks == 0:
        raise PreventUpdate
    
    # Input validation
    if user_string in ["",None]:
        response = "N/A"
        return response, response, response, response, response, response, response, response, response, response, response, response, response
    
    # Import recon functions
    from pages.dashboard.recon_users import FindUser, ReconUserMemberships, ReconUserAssignedApps

    # Execute recon
    user_id, user_upn, user_display_name, user_mail, user_job_title, user_off_location, user_phone = FindUser(user_string)
    groups_count, role_count, group_membership, role_assigned = ReconUserMemberships(user_id)
    app_assigned_count, user_app_assignments = ReconUserAssignedApps(user_id)

    return user_display_name, user_id, user_upn, user_mail, user_job_title, user_off_location, user_phone, groups_count, role_count, group_membership, role_assigned, app_assigned_count, user_app_assignments

'''C017 - Callback to populate Azure access info dynamically based on selected subscription'''
@app.callback(
        Output(component_id = "azure-access-info-div", component_property = "children"), 
        Input(component_id = "interval-to-trigger-initialization-check", component_property = "n_intervals"), 
        Input(component_id = "azure-subscription-selector-dropdown", component_property = "value"))
def generate_azure_access_info_callback(n_intervals, value):
    return generate_azure_access_info(value)

'''C018 - Callback to generate Azure subscription options in Access dropdown'''
@app.callback(
        Output(component_id = "azure-subscription-selector-dropdown", component_property = "options"), 
        Input(component_id = "azure-subscription-selector-dropdown", component_property = "title"))
def generate_azure_sub_dropdown_callback(title):
    if title == None:
        all_subscriptions = []
        
        for subs in AzureAccess().get_account_available_subscriptions():
            selected_value = subs.get("id")
            all_subscriptions.append(
                {
                    'label': html.Div(subs.get("name"), className="text-dark"), 'value': selected_value
                }
            )

        return all_subscriptions

'''C019 - Callback to generate attack sequence visualization in Automator'''
@app.callback(
    Output("playbook-visualization-container", "children"),
    [Input({"type": "playbook-card-click", "index": ALL}, "n_clicks")],
    prevent_initial_call=True
)
def update_visualization(n_clicks):
    """Update the visualization when a playbook is selected"""
    if not callback_context.triggered:
        raise PreventUpdate
    
    # Get the triggered component's ID
    triggered = callback_context.triggered[0]
    prop_id = json.loads(triggered['prop_id'].rsplit('.',1)[0])
    
    if triggered['value'] is None:  # No clicks yet
        raise PreventUpdate
        
    playbook_id = prop_id['index']
    
    try:
        pb_config = Playbook(playbook_id)
        # Return both the visualization and some playbook info
        return html.Div([
            html.H4(f"Playbook: {pb_config.name}", className="mb-3 text-light"),
            html.Div(playbook_viz_generator(pb_config.name), className="mb-3"),
            dbc.Card([
                dbc.CardBody([
                    html.H5("Playbook Details", className="card-title"),
                    html.P(f"Author: {pb_config.author}", className="mb-2"),
                    html.P(f"Created: {pb_config.creation_date}", className="mb-2"),
                    html.P(f"Total Steps: {pb_config.steps}", className="mb-2"),
                    html.P(f"Description: {pb_config.description}", className="mb-0")
                ])
            ], className="bg-dark text-light border-secondary")
        ])
    except Exception as e:
        return html.Div([
            html.H4("Error Loading Visualization", className="text-danger"),
            html.P(str(e), className="text-muted")
        ], className="p-3")

'''C020 - Callback to execute attack sequence in automator view'''
@app.callback(
    Output("execution-progress-offcanvas", "is_open", allow_duplicate=True),
    Output("app-notification", "is_open", allow_duplicate=True),
    Output("app-notification", "children", allow_duplicate=True),
    Output("app-error-display-modal", "is_open", allow_duplicate=True),
    Output("app-error-display-modal-body", "children", allow_duplicate=True),
    Output("selected-playbook-data", "data", allow_duplicate=True),
    Output("execution-interval", "disabled", allow_duplicate=True),
    Input({'type': 'execute-playbook-button', 'index': ALL}, 'n_clicks'),
    prevent_initial_call=True
)
def execute_playbook_callback(n_clicks):
    """Execute playbook and initialize progress tracking"""
    if not any(n_clicks):
        raise PreventUpdate
        
    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate
        
    # Get clicked playbook
    button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
    playbook_file = eval(button_id)['index']
    
    try:
        # Execute playbook in background thread
        def execute_playbook():
            playbook = Playbook(playbook_file)
            playbook.execute()
            
        execution_thread = threading.Thread(target=execute_playbook)
        execution_thread.daemon = True
        execution_thread.start()
        
        return True, True, "Playbook Execution Started", False, "", playbook_file, False
        
    except PlaybookError as e:
        error_msg = f"Playbook Execution Failed: {str(e.message)}"
        return False, False, "", True, error_msg, None, True
    except Exception as e:
        error_msg = f"Unexpected Error: {str(e)}"
        return False, False, "", True, error_msg, None, True

'''C021 - Callback to open attack scheduler off canvas'''
@app.callback(
        Output(component_id = "automator-offcanvas", component_property = "is_open", allow_duplicate= True), 
        Output(component_id = "automator-offcanvas", component_property = "title", allow_duplicate= True),
        Output(component_id = "automator-offcanvas", component_property = "children", allow_duplicate= True),
        Output(component_id="selected-playbook-data", component_property="data", allow_duplicate= True),
        Input({'type': 'open-schedule-win-playbook-button', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True
)
def toggle_pb_schedule_canvas_callback(n_clicks):
    if not any(n_clicks):
        raise PreventUpdate
    
    # Find which button was clicked
    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    # Extract playbook name from context
    button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
    selected_pb_name = eval(button_id)['index']

    return True, html.H3(["Schedule Playbook"]), schedule_pb_div, selected_pb_name

'''C022 - Callback to create new automator schedule'''
@app.callback(
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), 
        Output(component_id = "automator-offcanvas", component_property = "is_open", allow_duplicate=True),
        State(component_id="selected-playbook-data", component_property="data"),
        State(component_id = "set-time-input", component_property = "value"), 
        State(component_id = "automator-date-range-picker", component_property = "start_date"), 
        State(component_id = "automator-date-range-picker", component_property = "end_date"), 
        State(component_id = "schedule-repeat-boolean", component_property = "on"), 
        State(component_id = "repeat-options-dropdown", component_property = "value"), 
        State(component_id = "schedule-name-input", component_property = "value"), 
        Input(component_id = "schedule-playbook-button", component_property = "n_clicks"), 
        prevent_initial_call=True)
def create_new_schedule_callback(selected_pb_data, execution_time, start_date, end_date, repeat_flag, repeat_frequency, schedule_name, n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    
    if selected_pb_data == None:
        raise PreventUpdate
    
    playbook_id = selected_pb_data
    # Create new schedule
    AddNewSchedule(schedule_name, playbook_id, start_date, end_date, execution_time, repeat_flag, repeat_frequency)

    # Send notification after new schedule is created and close scheduler off canvas
    return True, "Playbook Scheduled", False

'''C023 - Callback to export playbook'''
@app.callback(
        Output(component_id = "app-download-sink", component_property = "data", allow_duplicate = True), 
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True),
        Output(component_id = "app-error-display-modal", component_property = "is_open", allow_duplicate=True),
        Output(component_id = "app-error-display-modal-body", component_property = "children", allow_duplicate=True),  
        State(component_id="selected-playbook-data", component_property="data"),
        State(component_id = "export-playbook-mask-param-boolean", component_property = "on"),
        State(component_id = "export-playbook-filename-text-input", component_property = "value"),
        Input(component_id = "export-playbook-button", component_property = "n_clicks"), 
        prevent_initial_call=True)
def export_playbook_callback(selected_pb_data, mask_param, export_file_name, n_clicks):
    if n_clicks == 0:
        raise PreventUpdate

    playbook_file = selected_pb_data
    playbook = Playbook(playbook_file)
    
    if not export_file_name:
        export_file_base_name = "Halberd_Playbook" # Set default file name
        export_file_name = export_file_base_name+"-"+(playbook.name).replace(" ", "_")+".yml"
    
    # Export playbook
    playbook_export_file_path = playbook.export(export_file = export_file_name, include_params=not(mask_param))

    # Download playbook and send app notification
    return dcc.send_file(playbook_export_file_path), True, "Playbook Exported", False, ""

'''C024 - Callback to import playbook'''
@app.callback(
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True),
        Output(component_id = "app-error-display-modal", component_property = "is_open", allow_duplicate=True),
        Output(component_id = "app-error-display-modal-body", component_property = "children", allow_duplicate=True), 
        Output('playbook-list-container', 'children', allow_duplicate=True),
        Output("playbook-stats", "children", allow_duplicate=True),
        Input(component_id = 'import-pb-button', component_property = 'n_clicks'), 
        Input(component_id = 'upload-playbook', component_property = 'contents'), 
        prevent_initial_call=True)
def import_playbook_callback(n_clicks, file_contents):
    if n_clicks == 0:
        raise PreventUpdate

    if file_contents:
        try:
            # Import playbook
            Playbook.import_playbook(file_contents)

            # Refresh the playbook list
            playbooks = GetAllPlaybooks()
            playbook_items = []
            
            for pb_file in playbooks:
                try:
                    pb_config = Playbook(pb_file)
                    # Apply search filter if query exists
                    playbook_items.append(create_playbook_item(pb_config))
                except Exception as e:
                    print(f"Error loading playbook {pb_file}: {str(e)}")
            
            # Generate stats
            stats = get_playbook_stats()
            stats_text = (f"{stats['total_playbooks']} playbooks loaded • "
                        f"Last sync: {stats['last_sync'].strftime('%I:%M %p') if stats['last_sync'] else 'never'}")

            # Import success - display notification and update playbook list    
            return True, "Playbook Imported", False, "", playbook_items, stats_text
        except Exception as e:
            # Display error in modal pop up
            return False, "", True, str(e), no_update, no_update
    else:
        raise PreventUpdate

'''C025 - Callback to add technique as step to playbook'''
@app.callback(
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

'''C026 - Callback to open playbook creator off canvas'''
@app.callback(
        Output(component_id = "automator-offcanvas", component_property = "is_open", allow_duplicate= True), 
        Output(component_id = "automator-offcanvas", component_property = "title", allow_duplicate= True),
        Output(component_id = "automator-offcanvas", component_property = "children", allow_duplicate= True),
        Input(component_id = 'open-creator-win-playbook-button', component_property= 'n_clicks'),
        prevent_initial_call=True
)
def toggle_pb_creator_canvas_callback(n_clicks):
    if n_clicks:
        return True, [html.H3("Create New Playbook")], generate_playbook_creator_offcanvas()

    raise PreventUpdate

'''C027 - Callback to create new playbook'''
@app.callback(
        Output(component_id = "playbook-creator-modal", component_property = "is_open", allow_duplicate=True),  
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), 
        Output(component_id = "app-error-display-modal", component_property = "is_open", allow_duplicate=True),
        Output(component_id = "app-error-display-modal-body", component_property = "children", allow_duplicate=True),
        State(component_id = "pb-name-input", component_property = "value"), 
        State(component_id = "pb-desc-input", component_property = "value"), 
        State(component_id = "pb-author-input", component_property = "value"), 
        State(component_id = "pb-refs-input", component_property = "value"), 
        Input(component_id = "create-playbook-button", component_property = "n_clicks"), prevent_initial_call=True
    )
def create_new_pb_callback(pb_name, pb_desc, pb_author, pb_references, n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    
    try:
        new_playbook = Playbook.create_new(
            name= pb_name,
            author= pb_author,
            description= pb_desc,
            references=[pb_references]
        )
        return False, True, f"New Playbook Created : {new_playbook.name}", False, ""
    except Exception as e:
        return True, False, "", True, str(e)
    
'''C028 - Callback to display technique info from playbook node in modal'''
@app.callback(
        Output(component_id = "app-technique-info-display-modal-body", component_property = "children"),
        Output(component_id = "app-technique-info-display-modal", component_property = "is_open"),
        Input(component_id = "auto-attack-sequence-cytoscape-nodes", component_property = "tapNodeData"),
        [State(component_id = "app-technique-info-display-modal", component_property = "is_open")], 
        prevent_initial_call=True
    )
def toggle_t_info_modal_callback(data, is_open):
    if data:
        # Extract module_id from node label
        if data['label'] != "None":
            info = data['info']
        else:
            raise PreventUpdate
        
        if info == "time":
            # Display time gap
            wait_time = data['label']
            return [html.B(f"Time Gap : {wait_time} seconds")], True
        else:
            # Display module info
            pb_step_info = data['info']
            step_data = next(iter(pb_step_info.items()))
            module_id = step_data[1]['Module']
            return generate_technique_info(module_id), not is_open
    else:
        raise PreventUpdate
        
'''C029 - Callback to display playbook node data on hover (deprecated)'''

'''C030 - Callback to open/close add to playbook modal on Attack page'''
@app.callback(
    Output(component_id = "add-to-playbook-modal", component_property = "is_open"),
    [
        Input(component_id = "open-add-to-playbook-modal-button", component_property = "n_clicks"), 
        Input(component_id = "close-add-to-playbook-modal-button", component_property = "n_clicks"), 
        Input(component_id = "confirm-add-to-playbook-modal-button", component_property = "n_clicks")
    ],
    [State(component_id = "add-to-playbook-modal", component_property = "is_open")],
    prevent_initial_call=True
)
def toggle_add_to_pb_modal_callback(n1, n2, n3, is_open):
    if n1 or n2 or n3:
        return not is_open
    return is_open

'''C031 - [Automator] Callback to generate/update playbook list in automator'''
@app.callback(
    Output("playbook-list-container", "children"),
    Output("playbook-stats", "children"),
    Input("playbook-search", "value"),
)
def update_playbook_list_callback(search_query):
    """Update the playbook list and stats based on search query"""
    # Get all available playbooks on system
    playbooks = GetAllPlaybooks()
    
    # Generate stats
    stats = get_playbook_stats()
    stats_text = (f"{stats['total_playbooks']} playbooks loaded • "f"Last sync: {stats['last_sync'].strftime('%I:%M %p') if stats['last_sync'] else 'never'}")
    
    # If no playbooks found on system
    if not playbooks:
        empty_playbook_list_div = html.Div(
            children=[
                html.Div([
                    DashIconify(
                        icon="mdi:information-outline", #Information icon
                        width=48,
                        height=48,
                        className="text-muted mb-3"
                    ),
                    html.P("Create or Import a playbook", # Default message when no playbook is selected
                            className="text-muted")
                ], className="text-center")
            ],
            className="d-flex justify-content-center align-items-center",
            style={'padding':'20px'}
        )
        return empty_playbook_list_div, stats_text
    
    # Initialize list to store playbook items
    playbook_items = []
    
    for pb_file in playbooks:
        try:
            pb_config = Playbook(pb_file)
            # Apply search filter if query exists
            if search_query and search_query.lower() not in pb_config.name.lower():
                continue
            playbook_items.append(create_playbook_item(pb_config))
        except Exception as e:
            print(f"Error loading playbook {pb_file}: {str(e)}")

    return playbook_items, stats_text
    
'''C032 - Callback to delete playbook from automator'''
@app.callback(
    Output('playbook-list-container', 'children', allow_duplicate=True),
    Output("playbook-stats", "children", allow_duplicate=True),
    Input({'type': 'delete-playbook-button', 'index': ALL}, 'n_clicks'),
    prevent_initial_call=True
)
def delete_playbook(n_clicks):
    """Handles playbook deletion"""
    if not any(n_clicks):
        return no_update
    
    # Find which button was clicked
    ctx = callback_context
    if not ctx.triggered:
        return no_update
    
    button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
    playbook_file = eval(button_id)['index']

    try:
        # Delete the playbook file
        os.remove(os.path.join(AUTOMATOR_PLAYBOOKS_DIR, playbook_file))
        
        # Refresh the playbook list
        playbooks = GetAllPlaybooks()

        # Generate stats
        stats = get_playbook_stats()
        stats_text = (f"{stats['total_playbooks']} playbooks loaded • "f"Last sync: {stats['last_sync'].strftime('%I:%M %p') if stats['last_sync'] else 'never'}")

        if not playbooks:
            empty_playbook_list_div = html.Div(
                children=[
                    html.Div([
                        DashIconify(
                            icon="mdi:information-outline", #Information icon
                            width=48,
                            height=48,
                            className="text-muted mb-3"
                        ),
                        html.P("Create or Import a playbook", # Default message when no playbook is selected
                                className="text-muted")
                    ], className="text-center")
                ],
                className="d-flex justify-content-center align-items-center",
                style={'padding':'20px'}
            )
            return empty_playbook_list_div, stats_text

        # Initialize list to store playbook items
        playbook_items = []
        
        for pb_file in playbooks:
            try:
                pb_config = Playbook(pb_file)
                # Apply search filter if query exists
                playbook_items.append(create_playbook_item(pb_config))
            except Exception as e:
                print(f"Error loading playbook {pb_file}: {str(e)}")
        
        
        
        return playbook_items, stats_text
    except Exception as e:
        print(f"Error deleting playbook {playbook_file}: {str(e)}")
        return no_update

'''C033 - Callback to open modal and display technique information from home techniques matrix'''
@app.callback(
    Output("app-technique-info-display-modal", "is_open", allow_duplicate=True),
    Output("app-technique-info-display-modal-body", "children", allow_duplicate = True),
    Input({"type": "technique", "index": dash.ALL}, "n_clicks"),
    State("app-technique-info-display-modal", "is_open"),
    prevent_initial_call=True
)
def toggle_app_modal_from_home_matrix_callback(n_clicks, is_open):
    # Prevent call back on page load
    if any(item is not None for item in n_clicks):
        if not dash.callback_context.triggered:
            return is_open, ""
        
        # Extract technique id
        triggered_id = dash.callback_context.triggered[0]["prop_id"]
        technique_id = eval(triggered_id.split(".")[0])["index"]

        # Generate technique information
        technique_details = generate_technique_info(technique_id)
        
        return not is_open, technique_details
    else:
        raise PreventUpdate
    
'''C034 - Callback to close the app technique info modal'''
@app.callback(
    Output("app-technique-info-display-modal", "is_open", allow_duplicate=True),
    Input("close-app-technique-info-display-modal", "n_clicks"),
    State("app-technique-info-display-modal", "is_open"),
    prevent_initial_call=True
)
def close_app_t_info_modal_callback(n_clicks, is_open):
    if n_clicks:
        return False
    return is_open

'''C035 - Callback to download report (deprecated)'''

'''C036 - Callback to display entity map node information'''
@app.callback(
    Output("entity-map-node-info-div", "children"),
    Input("entity-detection-cytoscape-nodes", "tapNodeData"),
)
def display_entity_map_node_info_callback(data):
    if not data:
        return "Click on a node to see more information."
    return f"Selected Node: {data['label']}"

'''C037 - Callback to view playbook details in automator off canvas (deprecated)'''

'''C038 - Callback to close the playbook information modal'''
@app.callback(
    Output("automator-playbook-info-display-modal", "is_open", allow_duplicate=True),
    Input("close-automator-playbook-info-display-modal", "n_clicks"),
    State("automator-playbook-info-display-modal", "is_open"),
    prevent_initial_call=True
)
def close_pb_info_modal_callback(n_clicks, is_open):
    if n_clicks:
        return False
    return is_open

'''C039 - Callback to download technique response data (deprecated)'''

'''C040 - Callback to open playbook export modal'''
@app.callback(
        Output(component_id = "automator-offcanvas", component_property = "is_open", allow_duplicate= True), 
        Output(component_id = "automator-offcanvas", component_property = "title", allow_duplicate= True),
        Output(component_id = "automator-offcanvas", component_property = "children", allow_duplicate= True),
        Output(component_id="selected-playbook-data", component_property="data", allow_duplicate= True),
        Input({'type': 'open-export-win-playbook-button', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True
)
def toggle_pb_export_canvas_callback(n_clicks):
    if not any(n_clicks):
        raise PreventUpdate
    
    # Find which button was clicked
    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    # Extract playbook name from context
    button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
    selected_pb_name = eval(button_id)['index']
    
    return True, [html.H3("Export Playbook")], export_pb_div, selected_pb_name

'''C041 - Callback to close the app error modal'''
@app.callback(
    Output("app-error-display-modal", "is_open", allow_duplicate=True),
    Input("close-app-error-display-modal", "n_clicks"),
    State("app-error-display-modal", "is_open"),
    prevent_initial_call=True
)
def close_app_error_modal_callback(n_clicks, is_open):
    if n_clicks:
        return False
    return is_open

'''C042 - Callback to generate AWS session options in AWS sessions dropdown'''
@app.callback(
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
                    'label': html.Div(session['session_name'], className="text-dark"), 
                    'value': session['session_name']
                }
            )

        return all_sessions

'''C043 - Callback to delete EntraID access token'''
@app.callback(
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

'''C044 - Callback to delete AWS session'''
@app.callback(
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

'''C045 - Callback to delete Azure session'''
@app.callback(
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

'''C046 - Callback to display access info button dynamically'''
@app.callback(
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
        return "No Access", "danger"

'''C046 - Callback to display access info in modal'''
@app.callback(
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
                    dbc.Col([
                        html.H4("Set Access", className="mt-2 mb-2"),    
                    ], md=4),
                    dbc.Col([
                        dcc.Dropdown(id=dropdown_id, className="mb-2")
                    ], md=8),
                ]),
                dcc.Loading(
                    id=f"{info_div_id}-loading",
                    type="default",
                    children=html.Div(id=info_div_id, className="p-3")
                ),
                dbc.Button("Remove Access", id=remove_button_id, color="danger", size="sm", className="mt-2")
            ],className="mb-4")
            
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
    
'''C047 - Callback to display technique output in technique output viewer'''
@app.callback(
        Output(component_id = "output-viewer-display-div", component_property = "children", allow_duplicate=True),
        Input(component_id = "trace-table", component_property = "selected_rows"),
        Input(component_id = "trace-table", component_property = "data"),
        prevent_initial_call=True
)
def display_technique_output_in_output_viewer_callback(selected_rows, data):
    if not selected_rows:
        return 'No cell selected'
    
    # Get the selected row's data and extract event ID
    selected_data = (data[selected_rows[0]])
    event_id = selected_data['Event ID']

    # Initialize output manager
    output_manager = OutputManager()
    # Get technique execution output by event id
    event_output = output_manager.get_output_by_event_id(event_id=event_id)

    # Display output
    return ParseTechniqueResponse(event_output['data'])

'''Attack dashboard callbacks'''
'''C048 - Callback to update metrics card in analyse dashboard'''
@app.callback(
    Output('metric-cards', 'children'),
    [Input('date-picker-range', 'start_date'),
     Input('date-picker-range', 'end_date')]
)
def update_metric_cards_callback(start_date, end_date):
    df = create_df_from_attack_logs()
    data = process_attack_data(df, pd.to_datetime(start_date), pd.to_datetime(end_date))
    
    return [
        html.Div([
            create_metric_card("Total Executions", data['total_executions'], "fa-flask", "#3498db"),
        ], style={'width': '23%', 'marginRight': '2%'}),
        html.Div([
            create_metric_card("Unique Techniques Executed", data['unique_techniques'], "fa-code-branch", "#2ecc71"),
        ], style={'width': '23%', 'marginRight': '2%'}),
        html.Div([
            create_metric_card("Attack Success Rate", 
                             f"{(data['status_counts'].get('success', 0) / data['total_executions'] * 100):.1f}%" if data['total_executions'] > 0 else "N/A", 
                             "fa-check-circle", "#e74c3c"),
        ], style={'width': '23%', 'marginRight': '2%'}),
        html.Div([
            create_metric_card("Avg Interval", 
                             f"{data['median_interval'].total_seconds()/60:.1f}min" if 'median_interval' in data else "N/A", 
                             "fa-clock", "#9b59b6"),
        ], style={'width': '23%'})
    ]

'''C049 - Callback to update graphs container in analyse dashboard'''
@app.callback(
    Output('graphs-container', 'children'),
    [Input('date-picker-range', 'start_date'),
     Input('date-picker-range', 'end_date')]
)
def update_graphs_callback(start_date, end_date):
    df = create_df_from_attack_logs()
    data = process_attack_data(df, pd.to_datetime(start_date), pd.to_datetime(end_date))
    
    return [
        # Timeline Graph
        html.Div([
            dcc.Graph(figure=create_timeline_graph(data)
            )
        ], style={'padding': '20px', 'borderRadius': '10px', 'boxShadow': '0 2px 4px rgba(0,0,0,0.1)', 'marginBottom': '20px'}, className="bg-dark"),
        
        # Surface Distribution and Success Rate Row
        html.Div([
            html.Div([
                dcc.Graph(figure=create_pie_chart(
                    data['surface_counts'].values,
                    data['surface_counts'].index,
                    'Attack Surface Distribution'
                )
            )
            ], style={'width': '48%', 'padding': '20px', 'borderRadius': '10px', 'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'}),
            
            html.Div([
                dcc.Graph(figure=create_bar_chart(
                    data['tactic_success'].index,
                    data['tactic_success']['success_rate'],
                    'Attack Success Rate by Tactic'
                )
                )
            ], style={'width': '48%', 'marginLeft': '4%', 'padding': '20px', 'borderRadius': '10px', 'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'})
        ], style={'display': 'flex', 'marginBottom': '20px'}, className="bg-dark"),
        
        # MITRE Tactics and Source Distribution Row
        html.Div([
            html.Div([
                dcc.Graph(figure=create_bar_chart(
                    data['tactic_counts'].index,
                    data['tactic_counts'].values,
                    'Attacks Executed by MITRE Tactics'
                )
                )
            ], style={'width': '48%', 'padding': '20px', 'borderRadius': '10px', 
                      'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'}),
            
            html.Div([
                dcc.Graph(figure=create_bar_chart(
                    data['source_counts'].index,
                    data['source_counts'].values,
                    'Attacks Executed by Source Entity'
                )
                )
            ], style={'width': '48%', 'marginLeft': '4%', 'padding': '20px', 'borderRadius': '10px', 'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'})
        ], style={'display': 'flex', 'marginBottom': '20px'}, className="bg-dark"),
        
        # Top Techniques Row
        html.Div([
            dcc.Graph(figure=create_bar_chart(
                data['technique_counts'].values,
                data['technique_counts'].index,
                'Most Executed Techniques',
                orientation='h'
            )
            )
        ], style={'padding': '20px', 'borderRadius': '10px', 'boxShadow': '0 2px 4px rgba(0,0,0,0.1)', 'marginBottom': '20px'}, className="bg-dark")
    ]

'''C050 - Callback to update footer stats in analyse dashboard'''
@app.callback(
    Output('footer-stats', 'children'),
    [Input('date-picker-range', 'start_date'),
     Input('date-picker-range', 'end_date')]
)
def update_footer_stats_callback(start_date, end_date):
    df = create_df_from_attack_logs()
    data = process_attack_data(df, pd.to_datetime(start_date), pd.to_datetime(end_date))
    
    return html.Div([
        html.H3('Execution Statistics', style={'marginBottom': '15px'}),
        html.P([
            f"Test Duration: {str(data['testing_period']['duration']).split('.')[0]} | ",
            f"Total Attacks: {data['total_executions']} | ",
            f"Unique Techniques: {data['unique_techniques']} | ",
            f"Average Success Rate: {(data['status_counts'].get('success', 0) / data['total_executions'] * 100):.1f}%" if data['total_executions'] > 0 else "N/A"
        ], style={'color': '#7f8c8d'})
    ], style={'textAlign': 'center', 'padding': '20px', 'borderRadius': '10px', 'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'}, className="bg-dark")

'''Create new playbook functionality callbacks'''
'''C051 - [Playbook Creator] Callback to generate/update parameter fields from selected technique'''
@app.callback(
    Output({"type": "step-params-container", "index": MATCH}, "children"),
    Input({"type": "step-module-dropdown", "index": MATCH}, "value"),
    prevent_initial_call=True
)
def update_step_parameters(module_id):
    """Update parameter fields based on selected module"""
    if not module_id:
        return []
    
    technique = TechniqueRegistry.get_technique(module_id)()
    params = technique.get_parameters()
    
    if not params:
        return html.P("No parameters required", className="text-muted")
    
    param_inputs = []
    for param_name, param_config in params.items():
        required = param_config.get("required", False)
        label_text = f"{param_config['name']} {'*' if required else ''}"
        
        input_type = param_config.get("input_field_type", "text")
        
        # Create the appropriate input element
        if input_type == "bool":
            input_elem = daq.BooleanSwitch(
                id={"type": "param-input", "param": param_name},
                on=param_config.get("default", False)
            )
        else:
            # Add any input validation based on technique requirements
            input_props = {
                "type": input_type,
                "id": {"type": "param-input", "param": param_name},
                "placeholder": param_config.get("default", ""),
                "className": "bg-dark text-light",
                "required": required
            }
            
            # Add any additional validation attributes
            if input_type == "number":
                input_props.update({
                    "min": param_config.get("min", None),
                    "max": param_config.get("max", None),
                    "step": param_config.get("step", None)
                })
            
            input_elem = dbc.Input(**input_props)
        
        # Add description or help text if available
        help_text = None
        if param_config.get("description"):
            help_text = html.Small(
                param_config["description"],
                className="text-muted d-block mt-1"
            )
        
        param_inputs.append(
            dbc.Row([
                dbc.Col([
                    dbc.Label(label_text),
                    input_elem,
                    help_text
                ])
            ], className="mb-3")
        )
    
    return param_inputs

'''C052 - [Playbook Creator] Callback to add a new step in playbook'''
@app.callback(
    Output("playbook-steps-container", "children"),
    Input("add-playbook-step-button", "n_clicks"),
    State("playbook-steps-container", "children"),
    prevent_initial_call=True
)
def add_playbook_step(n_clicks, current_steps):
    """Add a new step form to the playbook creator"""
    if n_clicks:
        new_step_number = len(current_steps) + 1
        return current_steps + [generate_step_form(new_step_number)]
    return current_steps

'''C053 - [Playbook Creator] Callback to remove a step from playbook'''
@app.callback(
    Output("playbook-steps-container", "children", allow_duplicate=True),
    Input({"type": "remove-step-button", "index": ALL}, "n_clicks"),
    State("playbook-steps-container", "children"),
    prevent_initial_call=True
)
def remove_playbook_step(n_clicks, current_steps):
    """Remove a step from the playbook creator"""
    if not any(n_clicks):
        raise PreventUpdate
    
    # Find which button was clicked
    ctx = dash.callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    button_id = json.loads(ctx.triggered[0]["prop_id"].rsplit(".")[0])
    step_to_remove = button_id["index"]

    # Remove the step and renumber remaining steps
    remaining_steps = [step for step in current_steps if int(step["props"]["children"][0]["props"]["children"][0]["props"]["children"][0]["props"]["children"][0]["props"]["children"].split()[-1]) != step_to_remove]
    renumbered_steps = [generate_step_form(i+1) for i in range(len(remaining_steps))]
    
    return renumbered_steps

'''C054 - [Playbook Creator] Callback to create a new playbook from offcanvas configuration'''
@app.callback(
    Output("app-notification", "is_open", allow_duplicate=True),
    Output("app-notification", "children", allow_duplicate=True),
    Output("app-error-display-modal", "is_open", allow_duplicate=True),
    Output("app-error-display-modal-body", "children", allow_duplicate=True),
    Output("automator-offcanvas", "is_open", allow_duplicate=True),
    Output('playbook-list-container', 'children', allow_duplicate=True),
    Output("playbook-stats", "children", allow_duplicate=True),
    Input("create-playbook-offcanvas-button", "n_clicks"),
    [
         State("pb-name-input-offcanvas", "value"),
        State("pb-desc-input-offcanvas", "value"),
        State("pb-author-input-offcanvas", "value"),
        State("pb-refs-input-offcanvas", "value"),
        State({"type": "step-module-dropdown", "index": ALL}, "value"),
        State({"type": "step-wait-input", "index": ALL}, "value"),
        State({"type": "param-input", "param": ALL}, "value"),
        State({"type": "param-input", "param": ALL}, "id")
    ],
    prevent_initial_call=True
)
def create_playbook_from_offcanvas(n_clicks, name, desc, author, refs, modules, waits, param_values, param_ids):
    """Create a new playbook from the off-canvas form data"""
    if not n_clicks:
        raise PreventUpdate
    
    try:
        # Validate required fields
        if not all([name, desc, author]):
            raise ValueError("Please fill in all required fields")
        
        if not any(modules):
            raise ValueError("At least one step is required")
        
        # Create new playbook
        new_playbook = Playbook.create_new(
            name=name,
            author=author,
            description=desc,
            references=[refs] if refs else None
        )
        
        # Group parameters by step
        step_params = {}
        for i, module in enumerate(modules):
            if module:  # If module is selected
                # Get technique parameters configuration
                technique = TechniqueRegistry.get_technique(module)()
                technique_params = technique.get_parameters()
                
                # Initialize params dict for this step
                step_params[i] = {}
                
                # Match parameters with their values for this step's technique
                for param_id, param_value in zip(param_ids, param_values):
                    param_name = param_id['param']
                    if param_name in technique_params:
                        # Convert empty strings to None for optional parameters
                        if param_value == "" and not technique_params[param_name].get('required', False):
                            param_value = None
                        step_params[i][param_name] = param_value
        
        # Add steps with their parameters
        for i, (module, wait) in enumerate(zip(modules, waits)):
            if module:  # Only add steps with selected modules
                new_step = PlaybookStep(
                    module=module,
                    params=step_params.get(i, {}),  # Get parameters for this step
                    wait=int(wait) if wait else 0
                )
                new_playbook.add_step(new_step, i + 1)
        
        # get updated list of available playbooks
        playbooks = GetAllPlaybooks()
        playbook_items = []
        
        for pb_file in playbooks:
            try:
                pb_config = Playbook(pb_file)
                # Apply search filter if query exists
                playbook_items.append(create_playbook_item(pb_config))
            except Exception as e:
                print(f"Error loading playbook {pb_file}: {str(e)}")
        
        stats = get_playbook_stats()
        stats_text = (f"{stats['total_playbooks']} playbooks loaded • "f"Last sync: {stats['last_sync'].strftime('%I:%M %p') if stats['last_sync'] else 'never'}")

        return True, f"New Playbook Created: {name}", False, "", False, playbook_items, stats_text
    
    except Exception as e:
        return False, "", True, str(e), False, no_update, no_update
    
'''Playbook editor callbacks'''
'''C055 - [Playbook Editor] Callback to open playbook editor off canvas'''
@app.callback(
    Output("playbook-editor-offcanvas", "is_open", allow_duplicate = True),
    Output(component_id="selected-playbook-data-editor-memory-store", component_property="data", allow_duplicate= True),
    Input({'type': 'edit-playbook-button', 'index': ALL}, 'n_clicks'),
    prevent_initial_call=True
)
def update_editable_playbook_view(n_clicks):
    if not any(n_clicks):
        raise PreventUpdate
    
    # Find which button was clicked
    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    # Extract playbook file name from context
    button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
    selected_pb = eval(button_id)['index']

    return True, selected_pb

'''C056 - [Playbook Editor] Callback to load & display existing playbook information'''
@app.callback(
    [
        Output("pb-name-input-editor", "value"),
        Output("pb-desc-input-editor", "value"),
        Output("pb-author-input-editor", "value"),
        Output("pb-refs-input-editor", "value"),
        Output("playbook-steps-editor-container", "children")
    ],
    Input({'type': 'edit-playbook-button', 'index': ALL}, 'n_clicks'),
    prevent_initial_call=True
)
def load_playbook_data(n_clicks):
    """Load existing playbook data into editor when opened"""
    if not n_clicks:
        raise PreventUpdate
    
    # Find which button was clicked
    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    # Extract playbook file name from context
    button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
    selected_pb = eval(button_id)['index']
    
    # Find the selected playbook
    try:
        playbook = Playbook(selected_pb)

        # Generate step forms with existing data
        steps = []
        for step_no, step_data in playbook.data['PB_Sequence'].items():
            step_form = dbc.Card([
                dbc.CardBody([
                    # Step header
                    dbc.Row([
                        dbc.Col([
                            html.H5(f"Step {step_no}", className="mb-3")
                        ], width=10),
                        dbc.Col([
                            html.Button(
                                html.I(className="bi bi-trash"),
                                id={"type": "remove-step-editor-button", "index": step_no},
                                className="btn btn-link text-danger",
                                style={"float": "right"}
                            ) if int(step_no) > 1 else None
                        ], width=2)
                    ]),
                    
                    # Module selector
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Module *"),
                            dcc.Dropdown(
                                id={"type": "step-module-dropdown-editor", "index": step_no},
                                options=[
                                    {"label": technique().name, "value": tid}
                                    for tid, technique in TechniqueRegistry.list_techniques().items()
                                ],
                                value=step_data.get('Module'),
                                placeholder="Select module",
                                className="bg-dark text-dark"
                            )
                        ])
                    ], className="mb-3"),
                    
                    # Parameters container
                    html.Div(
                        # Create parameter inputs if module data available
                        playbook_editor_create_parameter_inputs(
                            step_data.get('Module'),
                            step_data.get('Params', {})
                        ) if step_data.get('Module') else [],
                        id={"type": "step-params-container-editor", "index": step_no}
                    ),

                    # Wait time input
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Wait (seconds)"),
                            dbc.Input(
                                type="number",
                                id={"type": "step-wait-input-editor", "index": step_no},
                                value=step_data.get('Wait', 0),
                                placeholder="0",
                                min=0,
                                className="bg-dark text-light"
                            )
                        ])
                    ], className="mb-3"),
                ])
            ], className="mb-3")
            steps.append(step_form)
                
        return (
            playbook.name,
            playbook.description,
            playbook.author,
            ', '.join(playbook.references) if playbook.references else '',
            steps
        )
    except:
        raise PreventUpdate

'''C057 - [Playbook Editor] Callback to add a new step in existing playbook'''
@app.callback(
    Output("playbook-steps-editor-container", "children", allow_duplicate=True),
    Input("add-playbook-step-editor-button", "n_clicks"),
    State("playbook-steps-editor-container", "children"),
    prevent_initial_call=True
)
def add_playbook_step_editor(n_clicks, current_steps):
    """Add a new step form to the playbook editor"""
    if n_clicks:
        new_step_number = len(current_steps) + 1
        new_step = dbc.Card([
            dbc.CardBody([
                # Step header
                dbc.Row([
                    dbc.Col([
                        html.H5(f"Step {new_step_number}", className="mb-3")
                    ], width=10),
                    dbc.Col([
                        html.Button(
                            html.I(className="bi bi-trash"),
                            id={"type": "remove-step-editor-button", "index": new_step_number},
                            className="btn btn-link text-danger",
                            style={"float": "right"}
                        )
                    ], width=2)
                ]),
                
                # Module selector
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Module *"),
                        dcc.Dropdown(
                            id={"type": "step-module-dropdown-editor", "index": new_step_number},
                            options=[
                                {"label": technique().name, "value": tid}
                                for tid, technique in TechniqueRegistry.list_techniques().items()
                            ],
                            placeholder="Select module",
                            className="bg-dark"
                        )
                    ])
                ], className="mb-3"),
                
                # Wait time input
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Wait (seconds)"),
                        dbc.Input(
                            type="number",
                            id={"type": "step-wait-input-editor", "index": new_step_number},
                            placeholder="0",
                            min=0,
                            value=0,
                            className="bg-dark text-light"
                        )
                    ])
                ], className="mb-3"),
                
                # Parameters container (initially empty)
                html.Div(
                    id={"type": "step-params-container-editor", "index": new_step_number}
                )
            ])
        ], className="mb-3")
        
        return current_steps + [new_step]
    return current_steps

'''C058 - [Playbook Editor] Callback to update parameters on technique change from dropdown'''
@app.callback(
    Output({"type": "step-params-container-editor", "index": MATCH}, "children"),
    Input({"type": "step-module-dropdown-editor", "index": MATCH}, "value"),
    prevent_initial_call=True
)
def update_step_parameters_editor(module_id):
    """Update parameter fields when module selection changes"""
    if not module_id:
        return []
    
    return playbook_editor_create_parameter_inputs(module_id)

@app.callback(
    Output("app-notification", "is_open", allow_duplicate=True),
    Output("app-notification", "children", allow_duplicate=True),
    Output("app-error-display-modal", "is_open", allow_duplicate=True),
    Output("app-error-display-modal-body", "children", allow_duplicate=True),
    Output("playbook-editor-offcanvas", "is_open", allow_duplicate = True),
    Input("update-playbook-editor-button", "n_clicks"),
    [
        State("pb-name-input-editor", "value"),
        State("pb-desc-input-editor", "value"),
        State("pb-author-input-editor", "value"),
        State("pb-refs-input-editor", "value"),
        State({"type": "step-module-dropdown-editor", "index": ALL}, "value"),
        State({"type": "step-wait-input-editor", "index": ALL}, "value"),
        State({"type": "param-input-editor", "param": ALL}, "value"),
        State({"type": "param-input-editor", "param": ALL}, "id"),
        State("selected-playbook-data-editor-memory-store", "data"),
    ],
    prevent_initial_call=True
)
def update_playbook_from_editor(n_clicks, name, desc, author, refs, modules, waits, param_values, param_ids, selected_playbook):
    """Update existing playbook from editor data"""
    if not n_clicks:
        raise PreventUpdate

    try:
        # Find the selected playbook
        playbook = Playbook(selected_playbook)
        # Update playbook metadata
        playbook.data['PB_Name'] = name
        playbook.data['PB_Description'] = desc
        playbook.data['PB_Author'] = author
        playbook.data['PB_References'] = [ref.strip() for ref in refs.split(',')] if refs else []
        
        # Clear existing sequence
        playbook.data['PB_Sequence'] = {}
        
        # Group parameters by step
        step_params = {}
        for i, module in enumerate(modules):
            if module:
                technique = TechniqueRegistry.get_technique(module)()
                technique_params = technique.get_parameters()
                step_params[i] = {}
                
                for param_id, param_value in zip(param_ids, param_values):
                    param_name = param_id['param']
                    if param_name in technique_params:
                        if param_value == "" and not technique_params[param_name].get('required', False):
                            param_value = None
                        step_params[i][param_name] = param_value
        
        # Add updated steps
        for i, (module, wait) in enumerate(zip(modules, waits)):
            if module:
                playbook.data['PB_Sequence'][i + 1] = {
                    'Module': module,
                    'Params': step_params.get(i, {}),
                    'Wait': int(wait) if wait else 0
                }
        
        # Save updated playbook
        playbook.save()
        return True, f"Playbook Updated: {name}", False, "", False
        
    except Exception as e:
        return False, "", True, str(e), False

'''C059 - [Playbook Editor] Callback to remove step from playbook and update the playbook steps'''
@app.callback(
    Output("playbook-steps-editor-container", "children", allow_duplicate=True),
    Input({"type": "remove-step-editor-button", "index": ALL}, "n_clicks"),
    State("playbook-steps-editor-container", "children"),
    prevent_initial_call=True
)
def remove_playbook_step_editor(n_clicks, current_steps):
    """Remove a step from the playbook editor and renumber remaining steps"""
    if not any(n_clicks) or not current_steps:
        raise PreventUpdate
    
    # Find which button was clicked
    ctx = dash.callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    try:
        button_id = json.loads(ctx.triggered[0]["prop_id"].split(".")[0])
        step_to_remove = button_id["index"]
        
        # Create new list without the removed step
        remaining_steps = []
        new_step_number = 1
        
        for step in current_steps:
            # Extract current step number from the card
            current_step_header = step["props"]["children"]["props"]["children"][0]["props"]["children"][0]["props"]["children"]["children"]
            current_step_num = int(current_step_header.split()[1])
            
            if current_step_num != step_to_remove:
                # Update step number in header
                step["props"]["children"]["props"]["children"][0]["props"]["children"][0]["props"]["children"]["children"] = f"Step {new_step_number}"
                
                # Update all component IDs that contain step number
                for component in [
                    {"type": "remove-step-editor-button", "location": [0, "props", "children", 1, "props", "children", "props", "id"]},
                    {"type": "step-module-dropdown-editor", "location": [1, "props", "children", 0, "props", "children", 1, "props", "id"]},
                    {"type": "step-wait-input-editor", "location": [2, "props", "children", 0, "props", "children", 1, "props", "id"]},
                    {"type": "step-params-container-editor", "location": [3, "props", "id"]}
                ]:
                    try:
                        # Navigate to the component's location
                        current = step["props"]["children"]["props"]["children"]
                        for loc in component["location"][:-1]:
                            current = current[loc]
                        # Update the ID
                        current[component["location"][-1]]["index"] = new_step_number
                    except (KeyError, IndexError, TypeError):
                        continue
                
                remaining_steps.append(step)
                new_step_number += 1
        
        return remaining_steps
    except Exception as e:
        print(f"Error in remove_playbook_step_editor: {str(e)}")
        raise PreventUpdate

'''C060 - [Playbook Progress Tracker] Callback to update the execution progress display'''
@app.callback(
    Output("playbook-execution-progress", "children"),
    Output("execution-interval", "disabled"),
    Input("execution-interval", "n_intervals"),
    State("selected-playbook-data", "data"),
    prevent_initial_call=True
)
def update_execution_progress(n_intervals, playbook_data):
    """Update the execution progress display"""
    if not playbook_data:
        raise PreventUpdate
        
    try:
        # Get playbook config
        playbook = Playbook(playbook_data)
        total_steps = len(playbook.data['PB_Sequence'])
        
        # Get latest execution folder
        execution_folders = [
            d for d in os.listdir(AUTOMATOR_OUTPUT_DIR)
            if d.startswith(f"{playbook.name}_")
        ]
        
        if not execution_folders:
            raise PreventUpdate
            
        latest_folder = max(execution_folders)
        execution_folder = os.path.join(AUTOMATOR_OUTPUT_DIR, latest_folder)
        
        # Get execution results
        results = parse_execution_report(execution_folder)
        active_step = len(results)
        
        # Create status cards for each step
        step_cards = []
        for step_no, step_data in playbook.data['PB_Sequence'].items():
            step_index = int(step_no) - 1
            
            # Determine step status
            status = None
            message = None
            is_active = False
            
            if step_index < len(results):
                status = results[step_index].get('status')
            elif step_index == len(results):
                is_active = True
                
            step_cards.append(
                create_step_progress_card(
                    step_number=step_no,
                    module_name=step_data['Module'],
                    status=status,
                    is_active=is_active,
                    message=message
                )
            )
        
        # Create progress tracker component
        progress_tracker = dbc.Card([
            dbc.CardHeader([
                dbc.Row([
                    dbc.Col(
                        html.H5("Execution Progress", className="mb-0"),
                        width=8
                    ),
                    dbc.Col(
                        html.Small(
                            f"Step {active_step} of {total_steps}",
                            className="text-muted"
                        ),
                        width=4,
                        className="text-end"
                    )
                ])
            ]),
            dbc.CardBody(step_cards)
        ], className="bg-dark text-light mb-4")
        
        # Check if execution is complete
        is_complete = active_step == total_steps
        
        return progress_tracker, is_complete
        
    except Exception as e:
        print(f"Error updating progress: {str(e)}")
        raise PreventUpdate

'''C061 - [Playbook Progress Tracker] Callback to handle the off-canvas visibility and button display'''
@app.callback(
    Output("execution-progress-offcanvas", "is_open", allow_duplicate=True),
    Output("view-progress-button-container", "style", allow_duplicate=True),
    Output("execution-interval", "disabled", allow_duplicate=True),
    [
        Input({'type': 'execute-playbook-button', 'index': ALL}, 'n_clicks'),
        Input("view-progress-button", "n_clicks")
    ],
    [
        State("execution-progress-offcanvas", "is_open")
    ],
    prevent_initial_call=True
)
def manage_progress_display(execute_clicks, view_clicks, is_open):
    """Manage progress display visibility"""
    ctx = dash.callback_context
    if not ctx.triggered:
        raise PreventUpdate
        
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    # Handle execute button clicks
    if "execute-playbook-button" in trigger_id:
        if any(click for click in execute_clicks if click):
            # Show button and open offcanvas
            return True, {"display": "block"}, False
            
    # Handle view progress button clicks
    elif trigger_id == "view-progress-button" and view_clicks:
        return not is_open, {"display": "block"}, False
        
    raise PreventUpdate

if __name__ == '__main__':
    # Run Initialization check
    run_initialization_check()
    # Initialize logger
    logger = setup_logger() 
    # Start application
    app.run_server(debug = True)