#!/usr/bin/env python3
import json
import dash
import datetime
import time
import boto3
import os
import dash_daq as daq
import dash_bootstrap_components as dbc
from dash import dcc, html, Patch, ALL
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
from core.EntraAuthFunctions import FetchSelectedToken, ExtractTokenInfo, SetSelectedToken, FetchAllTokens
from core.AzureFunctions import GetCurrentSubscriptionAccessInfo, GetAccountSubscriptionList, SetDefaultSubscription
from pages.dashboard.entity_map import GenerateEntityMappingGraph
from core.TechniqueExecutor import TechniqueInputs, ExecuteTechnique, ParseTechniqueResponse, LogEventOnTrigger
from core.AttackPlaybookVisualizer import AttackSequenceVizGenerator, EnrichNodeInfo
from core.Functions import DisplayTechniqueInfo, TacticMapGenerator, TechniqueMapGenerator, TechniqueOptionsGenerator, TabContentGenerator, InitializationCheck, DisplayPlaybookInfo, ExecutePlaybook, AddNewSchedule, Playbook, GetAllPlaybooks, ImportPlaybook, CreateNewPlaybook
from core.Constants import *

# Create Application
app = dash.Dash(__name__,  external_stylesheets=[dbc.themes.LUX, dbc.icons.BOOTSTRAP],title='Halberd', update_title='Loading...', suppress_callback_exceptions=True)

# Navigation bar layout
navbar = dbc.NavbarSimple(
    children=[
        dbc.NavItem(dbc.NavLink("Access", href="/access")),
        dbc.NavItem(dbc.NavLink("Attack", href="/attack")),
        dbc.NavItem(dbc.NavLink("Recon", href="/recon")),
        dbc.NavItem(dbc.NavLink("Automator", href="/automator")),
        dbc.NavItem(dbc.NavLink("Trace", href="/attack-trace")),
    ],
    brand= html.Div([
        dbc.Row(
                [
                    dbc.Col(html.Img(src="/assets/favicon.ico", height="30px")),
                    dbc.Col(html.Div("Halberd", className="text-danger")),
                ],
            ),
        ]),
    brand_href="/home",
    color="dark",
    dark=True,
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
        duration=5000,
        color="primary",
        style={"position": "fixed", "top": 66, "right": 10, "width": 350},
    ),
    dbc.Toast(
        children = "",
        id="app-notification",
        header="Notification",
        is_open=False,
        dismissable=True,
        duration=5000,
        color="primary",
        style={"position": "fixed", "top": 66, "right": 10, "width": 350},
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
])


'''C001 - Callback to update the page content based on the URL'''
@app.callback(Output('page-content', 'children'), [Input('url', 'pathname')])
def display_page(pathname):
    if pathname == '/home':
        from pages.home import page_layout
        return page_layout
    elif pathname == '/access':
        from pages.access import page_layout
        return page_layout
    elif pathname == '/attack':
        from pages.attack import page_layout
        return page_layout
    elif pathname == '/recon':
        from pages.recon import page_layout
        return page_layout
    elif pathname == '/attack-trace':
        from pages.attack_trace import GenerateAttackTraceView
        return GenerateAttackTraceView()
    elif pathname == '/automator':
        from pages.automator import page_layout
        return page_layout
    elif pathname == '/schedules':
        from pages.schedules import GenerateAutomatorSchedulesView
        return GenerateAutomatorSchedulesView()
    else:
        from pages.home import page_layout
        return page_layout

'''C002 - Callback to display tab content'''
@app.callback(Output("tabs-content-div", "children"), Input("attack-surface-tabs", "active_tab"))
def TabSwitcher(tab):
    tab_content = TabContentGenerator(tab)
    return tab_content

'''C003 - Callback to display options in Attack page'''
@app.callback(Output(component_id = "technique-options-div", component_property = "children"), Input(component_id = "attack-surface-tabs", component_property = "active_tab"), Input(component_id = "tactic-dropdown", component_property = "value"))
def DisplayAttackTechniqueOptions(tab, tactic):
    return TechniqueOptionsGenerator(tab, tactic)


'''C004 - Callback to display technique config'''
@app.callback(Output(component_id = "attack-config-div", component_property = "children"), Input(component_id = "attack-options-radio", component_property = "value"))
def DisplayAttackTechniqueConfig(t_id):
    technique_config = TechniqueInputs(t_id)

    config_div_elements = []

    config_div_display = Patch()
    config_div_display.clear()

    if len(technique_config) > 0:
        config_div_elements.append(html.H5("Attack Technique Config"))
        for config_field in technique_config:
            config_div_elements.append(dbc.Label(config_field['title']))

            if config_field['element_type'] == "daq.BooleanSwitch":
                config_div_elements.append(daq.BooleanSwitch(id = {"type": "technique-config-display-boolean-switch", "index": "input"}, on=False))
            
            if config_field['element_type'] == "dcc.Upload":
                config_div_elements.append(dcc.Upload(id = {"type": "technique-config-display-file-upload", "index": "file"}, children=html.Div([html.A('Drag and Drop or Select a File')]), style={'width': '100%', 'height': '60px', 'lineHeight': '60px', 'borderWidth': '1px', 'borderStyle': 'dashed', 'borderRadius': '5px', 'textAlign': 'center', 'margin': '10px'}))

            if config_field['element_type'] == "dcc.Input":
                config_div_elements.append(dbc.Input(
                    type = config_field['type'],
                    placeholder = config_field['placeholder'],
                    debounce = True,
                    id = {"type": "technique-config-display", "index": "input"},
                    className="bg-dark border",
                ))
                
            config_div_elements.append(html.Br(id="cosmetics"))

        config_div = html.Div(config_div_elements, className='divBorder d-grid col-6 mx-auto', style={'width' : '100%'})
        config_div_display.append(config_div)
    else:
        config_div_display.append(html.H5("Attack Technique Config"))
        config_div_display.append(html.B("No config required! Hit 'Execute'"))

    config_div_display.append(html.Br())
    config_div_display.append(
        (html.Div([
            dbc.Button("Execute Technique", id="technique-execute-button", n_clicks=0, color="danger"),
            html.Br(),
        ], className="d-grid col-6 mx-auto"))
    )
    config_div_display.append(html.Div([
            # opens modal and displays technique info in {app-technique-info-display-modal}
            dbc.Button("About Technique", id="technique-info-display-button", n_clicks=0, color="primary"), 
            html.Br(),
            dbc.Button("Add to Playbook", id="open-add-to-playbook-modal-button", n_clicks=0, color="secondary")
        ], style={'display': 'flex', 'justify-content': 'center', 'gap': '10px'})
    )
    
    config_div_display.append(
        html.Div(id='attack-technique-sink-hidden-div', style={'display':'none'}),
    )

    # create plabook dropdown content
    playbook_dropdown_options = []    
    for pb in GetAllPlaybooks():
        playbook_dropdown_options.append(
            {
                "label": html.Div([Playbook(pb).name], style={'font-size': 20}, className="text-dark"),
                "value": Playbook(pb).name,
            }
        )

    config_div_display.append(
        # create add to playbook modal
        dbc.Modal(
            [
                dbc.ModalHeader("Add Technique to Playbook"),
                dbc.ModalBody([
                    html.H6("Choose playbook to add current attack technique and its configuration"),
                    dcc.Dropdown(
                        options = playbook_dropdown_options, 
                        value = None, 
                        id='att-pb-selector-dropdown',
                        placeholder="Select Playbook"),
                    html.Br(),
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

'''C005 - Attack Execution Callback - Execute Technique'''
@app.callback(Output(component_id = "execution-output-div", component_property = "children"), Output(component_id = "technique-output-memory-store", component_property = "data"), Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), Input(component_id= "technique-execute-button", component_property= "n_clicks"), State(component_id = "attack-options-radio", component_property = "value"), State({"type": "technique-config-display", "index": ALL}, "value"), State({"type": "technique-config-display-boolean-switch", "index": ALL}, "on"), State({"type": "technique-config-display-file-upload", "index": ALL}, "contents"), prevent_initial_call = True)
def ExecuteTechniqueCallback(n_clicks, t_id, values, bool_on, file_content):
    '''The input callback can handle text inputs, boolean flags and file upload content'''
    if n_clicks == 0:
        raise PreventUpdate
    
    # if inputs also contains boolean flag and uploaded file content
    if bool_on and file_content:
        output = ExecuteTechnique(t_id, values, bool_on, file_content)
    # if inputs also contains boolean flag
    elif bool_on: 
        output = ExecuteTechnique(t_id, values, bool_on)
    # if input also contains uploaded file content
    elif file_content:
        output = ExecuteTechnique(t_id, values, file_content)
    else:
        output = ExecuteTechnique(t_id, values)
    
    # check if technique output is in the expected tuple format (success, raw_response, pretty_response)
    if isinstance(output, tuple) and len(output) == 3:
        success, raw_response, pretty_response = output

    # cleanup data for memorystore
    if isinstance(raw_response, (str, dict, list, tuple)):
        if isinstance(raw_response, dict):
            raw_response = {key: str(value) for key, value in raw_response.items()}
        elif isinstance(raw_response, (list, tuple)):
            raw_response = type(raw_response)(str(item) for item in raw_response)
    else:
        raw_response = {"Raw Response" : "Unavailable"}
    
    # return -> technique output, notification_on, notification_message 
    return ParseTechniqueResponse(output), raw_response if type(raw_response) in [str, dict, list, tuple] else {"Raw Response" : "Unavailable"}, True, "Technique Executed"
    
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

'''C007 - Callback to open/close Technique Info modal'''
@app.callback(Output(component_id = "app-technique-info-display-modal", component_property = "is_open", allow_duplicate=True),
              Output("app-technique-info-display-modal-body", "children", allow_duplicate = True), 
              Input(component_id= "technique-info-display-button", component_property= "n_clicks"),
              State(component_id = "attack-options-radio", component_property = "value"), 
              [State("app-technique-info-display-modal", "is_open")], prevent_initial_call=True
)
def DisplayAttackTechniqueConfig(n_clicks, t_id, is_open):
    if n_clicks == 0:
        raise PreventUpdate
    
    # get technique details
    technique_details = DisplayTechniqueInfo(t_id)
    
    return not is_open, technique_details

'''C008 - Callback to log executed technique'''
@app.callback(
    Output(component_id = "attack-technique-sink-hidden-div", component_property = "children"), 
    Input(component_id= "technique-execute-button", component_property= "n_clicks"),  
    Input(component_id = "tactic-dropdown", component_property = "value"), 
    Input(component_id = "attack-options-radio", component_property = "value"), 
    prevent_initial_call = True)
def LogEventOnTriggerCallback(n_clicks, tactic, technique):
    if n_clicks == 0:
        raise PreventUpdate

    return LogEventOnTrigger(tactic, technique)

'''C009 - Callback to download trace logs'''
@app.callback(
    Output("app-download-sink", "data"),
    Input("download-trace-logs-button", "n_clicks"),
    prevent_initial_call=True,
)
def DownloadTraceLogs(n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    return dcc.send_file(TRACE_LOG_FILE)

'''C010 - Callback to populate AWS access info'''
@app.callback(Output(component_id = "aws-access-info-div", component_property = "children"), Input(component_id = "interval-to-trigger-initialization-check", component_property = "n_intervals"))
def GenerateAccessInfoDivCallBack(n_intervals):
    info_output_div = []
    info_output_div.append(html.Br())
    info_output_div.append(html.H5("Access : "))

    sts_client = boto3.client('sts')
    
    try:
        session_info = sts_client.get_caller_identity()

        info_output_div.append(html.H5("Valid Session", className="text-success"))
        info_output_div.append(html.Br())
        info_output_div.append(html.Br())
        info_output_div.append(html.H5("User ID :"))
        info_output_div.append(html.Div(session_info['UserId']))
        info_output_div.append(html.Br())
        info_output_div.append(html.Br())
        info_output_div.append(html.H5("Account :"))
        info_output_div.append(html.Div(session_info['Account']))
        info_output_div.append(html.Br())
        info_output_div.append(html.Br())
        info_output_div.append(html.H5("ARN : "))
        info_output_div.append(html.Div(session_info['Arn']))
        
        return info_output_div
    except:
        
        info_output_div.append(html.Div("No Valid Session", className="text-danger"))
        return info_output_div

'''C011 - Callback to populate EntraID access info'''
@app.callback(Output(component_id = "access-info-div", component_property = "children"), Input(component_id = "interval-to-trigger-initialization-check", component_property = "n_intervals"))
def GenerateAccessInfoDivCallBack(n_intervals):
    access_token = FetchSelectedToken()
    access_info = ExtractTokenInfo(access_token)
    if access_info != None:
        info_output_div = []
        info_output_div.append(html.Br())
        for info in access_info:
            if info == 'Access Exp':
                if access_info['Access Exp'] < datetime.datetime.fromtimestamp(int(time.time()), tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'):
                    info_output_div += [
                        html.H5(f"{info} : "),
                        html.Div(f"{access_info[info]} UTC [Expired]", className="text-danger"),
                        html.Br(),
                        html.Br()
                        ]
                else:
                    info_output_div += [
                        html.H5(f"{info} : "),
                        html.Div(f"{access_info[info]} UTC [Valid]", className="text-success"),
                        html.Br(),
                        html.Br()
                        ]
            else:
                info_output_div += [
                    html.H5(f"{info} : "), 
                    html.Div(f"{access_info[info]}"), 
                    html.Br(), 
                    html.Br()
                    ]
        
        return info_output_div
    else:
        return "Failed to decode access token"

'''C012 - Callback to select Entra ID access token'''
@app.callback(Output(component_id = "access-info-div", component_property = "children",  allow_duplicate=True), Input(component_id = "token-selector-dropdown", component_property = "value"), prevent_initial_call=True)
def UpdateInfoOnTokenSelectCallBack(value):

    selected_token = json.loads(value)
    selected_token_entity = list(selected_token.keys())[0]
    selected_token_exp = list(selected_token.values())[0]

    for token in FetchAllTokens():
        token_info = ExtractTokenInfo(token)
        if token_info != None:
            if token_info['Entity'] == selected_token_entity and token_info['Access Exp'] == selected_token_exp:
                access_token = token
                break
        else:
            pass

    SetSelectedToken(access_token)

    access_info = ExtractTokenInfo(access_token)
    if access_info != None:
        info_output_div = []
        for info in access_info:
            info_output_div = []
        info_output_div.append(html.Br())
        for info in access_info:
            if info == 'Access Exp':
                if access_info['Access Exp'] < datetime.datetime.fromtimestamp(int(time.time()), tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'):
                    info_output_div += [
                        html.H5(f"{info} : "),
                        html.Div(f"{access_info[info]} UTC [Expired]", className="text-danger"),
                        html.Br(),
                        html.Br()
                        ]
                else:
                    info_output_div += [
                        html.H5(f"{info} : "),
                        html.Div(f"{access_info[info]} UTC [Valid]", className="text-success"),
                        html.Br(),
                        html.Br()
                        ]
            else:
                info_output_div += [
                    html.H5(f"{info} : "), 
                    html.Div(f"{access_info[info]}"), 
                    html.Br(), 
                    html.Br()
                    ]
        
        return info_output_div
    else:
        return "Failed to decode access token"


'''C013 - Callback to generate Entra ID token options in Access dropdown'''
@app.callback(Output(component_id = "token-selector-dropdown", component_property = "options"), Input(component_id = "token-selector-dropdown", component_property = "title"))
def GenerateDropdownOptionsCallBack(title):
    if title == None:
        all_tokens = []
        for token in FetchAllTokens():
            token_info = ExtractTokenInfo(token)
            if token_info != None:
                selected_value = {token_info.get('Entity') : token_info.get('Access Exp')}
                all_tokens.append(
                    {
                        'label': html.Div(token_info['Entity'], className="text-dark"), 'value': json.dumps(selected_value)
                    }
                )

        return all_tokens

'''C014 - Recon page tab switcher'''
@app.callback(Output("recon-content-div", "children"), Input("recon-target-tabs", "active_tab"))
def TabSwitcher(tab):
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
@app.callback(Output(component_id = "role-name-recon-div", component_property = "children"), Output(component_id = "role-template-id-recon-div", component_property = "children"), Output(component_id = "role-id-recon-div", component_property = "children"), Output(component_id = "role-member-count-recon-div", component_property = "children"), Output(component_id = "role-member-recon-div", component_property = "children"), Output(component_id = "role-description-recon-div", component_property = "children"), Input(component_id= "role-recon-start-button", component_property= "n_clicks"),Input(component_id = "role-recon-input", component_property = "value"))
def ExecuteRecon(n_clicks, role_name):
    if n_clicks == 0:
        raise PreventUpdate
    
    # input validation
    if role_name in ["",None]:
        response = "N/A"
        return response, response, response, response, response, response
    
    # import recon functions
    from pages.dashboard.recon_roles import FindRole, ReconRoleMembers
    
    # execute recon
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
def ExecuteRecon(n_clicks, user_string):
    if n_clicks == 0:
        raise PreventUpdate
    
    # input validation
    if user_string in ["",None]:
        response = "N/A"
        return response, response, response, response, response, response, response, response, response, response, response, response, response
    
    # import recon functions
    from pages.dashboard.recon_users import FindUser, ReconUserMemberships, ReconUserAssignedApps

    # execute recon
    user_id, user_upn, user_display_name, user_mail, user_job_title, user_off_location, user_phone = FindUser(user_string)
    groups_count, role_count, group_membership, role_assigned = ReconUserMemberships(user_id)
    app_assigned_count, user_app_assignments = ReconUserAssignedApps(user_id)

    return user_display_name, user_id, user_upn, user_mail, user_job_title, user_off_location, user_phone, groups_count, role_count, group_membership, role_assigned, app_assigned_count, user_app_assignments

'''C017 - Callback to populate Azure access info dynamically based on selected subscription'''
@app.callback(Output(component_id = "azure-access-info-div", component_property = "children"), Input(component_id = "interval-to-trigger-initialization-check", component_property = "n_intervals"), Input(component_id = "azure-subscription-selector-dropdown", component_property = "value"))
def GenerateAccessInfoDivCallBack(n_intervals, value):
    # n_intervals will refresh the access info periodically

    info_output_div = []
    info_output_div.append(html.Br())
    info_output_div.append(html.H5("Access : "))
    
    
    if value == None:
        # if no subscription has been selected, proceed with default subscription
        pass
    else:
        selected_subscription = value
        SetDefaultSubscription(selected_subscription)

    # get set subscription info
    current_access = GetCurrentSubscriptionAccessInfo()
    
    try:
        if current_access != None:
            # construct session info to display
            info_output_div.append(html.H5("Active Session", className="text-success"))
            info_output_div.append(html.Br())
            info_output_div.append(html.Br())
            info_output_div.append(html.H5("Environment Name :"))
            info_output_div.append(html.Div(current_access.get("environmentName", "N/A")))
            info_output_div.append(html.Br())
            info_output_div.append(html.Br())
            info_output_div.append(html.H5("Name : "))
            info_output_div.append(html.Div(current_access.get("name", "N/A")))
            info_output_div.append(html.Br())
            info_output_div.append(html.Br())
            info_output_div.append(html.H5("Subscription ID : "))
            info_output_div.append(html.Div(current_access.get("id", "N/A")))
            info_output_div.append(html.Br())
            info_output_div.append(html.Br())
            info_output_div.append(html.H5("Is Default : "))
            info_output_div.append(html.Div(str(current_access.get("isDefault", "N/A"))))
            info_output_div.append(html.Br())
            info_output_div.append(html.Br())
            info_output_div.append(html.H5("State : "))
            info_output_div.append(html.Div(current_access.get("state", "N/A")))
            info_output_div.append(html.Br())
            info_output_div.append(html.Br())
            info_output_div.append(html.H5("User : "))
            info_output_div.append(html.Div(current_access.get("user", "N/A").get("name","N/A")))
            info_output_div.append(html.Br())
            info_output_div.append(html.Br())
            info_output_div.append(html.H5("Tenant ID : "))
            info_output_div.append(html.Div(current_access.get("tenantId", "N/A")))
            info_output_div.append(html.Br())
            info_output_div.append(html.Br())
            info_output_div.append(html.H5("Home Tenant ID :"))
            info_output_div.append(html.Div(current_access.get("homeTenantId", "N/A")))
            
            return info_output_div
        else:
            info_output_div.append(html.Div("No Active Session", className="text-danger"))
            return info_output_div
    except:
        info_output_div.append(html.Div("No Active Session", className="text-danger"))
        return info_output_div

'''C018 - Callback to generate Azure subscription options in Access dropdown'''
@app.callback(Output(component_id = "azure-subscription-selector-dropdown", component_property = "options"), Input(component_id = "azure-subscription-selector-dropdown", component_property = "title"))
def GenerateDropdownOptionsCallBack(title):
    if title == None:
        all_subscriptions = []
        for subs in GetAccountSubscriptionList():
            selected_value = subs.get("id")
            all_subscriptions.append(
                {
                    'label': html.Div(subs.get("name"), className="text-dark"), 'value': selected_value
                }
            )

        return all_subscriptions

'''C019 - Callback to generate automated attack sequence visualization'''
@app.callback(Output(component_id = "attack-automator-path-display-div", component_property = "children"), Output(component_id = "playbook-node-data-div", component_property = "children", allow_duplicate= True), Input(component_id = "automator-pb-selector-dropdown", component_property = "value"), prevent_initial_call=True)
def DisplayAttackSequenceViz(selected_pb):
    if selected_pb:
        return AttackSequenceVizGenerator(selected_pb), DisplayPlaybookInfo(selected_pb) 
    else:
        raise PreventUpdate

'''C020 - Callback to execute attack sequence in automator view'''
@app.callback(Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), Input(component_id = "automator-pb-selector-dropdown", component_property = "value"), Input(component_id = "execute-sequence-button", component_property = "n_clicks"), prevent_initial_call=True)
def ExecuteAttackSequence(playbook_id, n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    
    if playbook_id == None:
        return True, "No Playbook Selected to Execute"
    
    # execute playbook
    ExecutePlaybook(playbook_id)
    
    return True, "Playbook Execution Completed"

'''C021 - Callback to open attack scheduler modal'''
@app.callback(Output(component_id = "scheduler-modal", component_property = "is_open"), [Input("toggle-scheduler-modal-open-button", "n_clicks"), Input("toggle-scheduler-modal-close-button", "n_clicks")], [State("scheduler-modal", "is_open")])
def toggle_modal(open_trigger, close_trigger, is_open):
    if open_trigger or close_trigger:
        return not is_open
    return is_open

'''C022 - Callback to create new automator schedule'''
@app.callback(Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), Output(component_id = "scheduler-modal", component_property = "is_open", allow_duplicate=True), Input(component_id = "automator-pb-selector-dropdown", component_property = "value"), Input(component_id = "set-time-input", component_property = "value"), Input(component_id = "automator-date-range-picker", component_property = "start_date"), Input(component_id = "automator-date-range-picker", component_property = "end_date"), Input(component_id = "schedule-repeat-boolean", component_property = "on"), Input(component_id = "repeat-options-dropdown", component_property = "value"), Input(component_id = "schedule-name-input", component_property = "value"), Input(component_id = "schedule-sequence-button", component_property = "n_clicks"), prevent_initial_call=True)
def CreateNewAutomatorSchedule(playbook_id, execution_time, start_date, end_date, repeat_flag, repeat_frequency, schedule_name, n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    
    # send notification if no playbook selected from dropdown
    if playbook_id == None:
        return True, "No Playbook Selected to Schedule", False
    
    # create new schedule
    AddNewSchedule(schedule_name, playbook_id, start_date, end_date, execution_time, repeat_flag, repeat_frequency)

    # send notification after new schedule is created
    return True, "Playbook Scheduled", False

'''C023 - Callback to export playbook'''
@app.callback(
        Output(component_id = "app-download-sink", component_property = "data", allow_duplicate = True), 
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), 
        State(component_id = "automator-pb-selector-dropdown", component_property = "value"), 
        Input(component_id = "export-pb-button", component_property = "n_clicks"), 
        prevent_initial_call=True)
def ExportAttackPlaybook(playbook_name, n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
        
    # if no playbook is selected, send notification
    if playbook_name == None:
        return None, True, "No Playbook Selected to Export"
    
    # get the selected playbook file location
    for pb in GetAllPlaybooks():
        pb_config = Playbook(pb)
        if  pb_config.name == playbook_name:
            playbook_file = pb_config.file

    # download playbook and send app notification
    return dcc.send_file(playbook_file), True, "Playbook Exported"

'''C024 - Callback to import playbook'''
@app.callback(
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), 
        Input(component_id = 'import-pb-button', component_property = 'n_clicks'), 
        Input(component_id = 'upload-playbook', component_property = 'contents'), 
        State(component_id = 'upload-playbook', component_property = 'filename'),
        prevent_initial_call=True)
def UploadHalberdPlaybook(n_clicks, contents, filename):
    if n_clicks == 0:
        raise PreventUpdate
    ImportPlaybook(contents, filename)
    return True, "Playbook Imported"

'''C025 - Callback to add technique to playbook'''
@app.callback(
        Output(component_id = "app-notification", component_property = "is_open"), 
        Output(component_id = "app-notification", component_property = "children"), 
        Input(component_id = "confirm-add-to-playbook-modal-button", component_property = "n_clicks"), 
        Input(component_id = "att-pb-selector-dropdown", component_property = "value"), 
        State(component_id = "attack-options-radio", component_property = "value"),
        State(component_id = {"type": "technique-config-display", "index": ALL}, component_property = "value"), 
        State(component_id = {"type": "technique-config-display-file-upload", "index": ALL}, component_property = "contents")
    )
def AddTechniqueToPlaybook(n_clicks, selected_pb, t_id, technique_input, file_content):
    if n_clicks == 0:
        raise PreventUpdate
    
    # if config has file as input
    if file_content:
        if selected_pb:
            for pb in GetAllPlaybooks():
                pb_config = Playbook(pb)
                if  pb_config.name == selected_pb:
                    break

        technique_input.append(file_content)
    
    else:
        if selected_pb:
            for pb in GetAllPlaybooks():
                pb_config = Playbook(pb)
                if  pb_config.name == selected_pb:
                    break
        
    # add technique to playbook
    pb_config.AddPlaybookStep(t_id, technique_input)
    # save and update new playbook config
    pb_config.SavePlaybook()

    return True, "Added to Playbook"

'''C026 - Callback to open playbook creator modal'''
@app.callback(Output(component_id = "playbook-creator-modal", component_property = "is_open"), [Input("pb-creator-modal-open-button", "n_clicks"), Input("pb-creator-modal-close-button", "n_clicks")], [State("playbook-creator-modal", "is_open")])
def toggle_modal(open_trigger, close_trigger, is_open):
    if open_trigger or close_trigger:
        return not is_open
    return is_open

'''C027 - Callback to create new playbook'''
@app.callback(
        Output(component_id = "hidden-div", component_property = "children", allow_duplicate=True), 
        Output(component_id = "playbook-creator-modal", component_property = "is_open", allow_duplicate=True),  
        State(component_id = "pb-name-input", component_property = "value"), 
        State(component_id = "pb-desc-input", component_property = "value"), 
        State(component_id = "pb-author-input", component_property = "value"), 
        State(component_id = "pb-refs-input", component_property = "value"), 
        Input(component_id = "create-playbook-button", component_property = "n_clicks"), prevent_initial_call=True
    )
def CreateNewPlaybookCallback(pb_name, pb_desc, pb_author, pb_references, n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    
    return CreateNewPlaybook(pb_name, pb_desc, pb_author, pb_references), False

'''C028 - Callback to display technique info from playbook node in modal'''
@app.callback(
        Output(component_id = "app-technique-info-display-modal-body", component_property = "children"),
        Output(component_id = "app-technique-info-display-modal", component_property = "is_open"),
        Input(component_id = "auto-attack-sequence-cytoscape-nodes", component_property = "tapNodeData"),
        [State(component_id = "app-technique-info-display-modal", component_property = "is_open")], 
        prevent_initial_call=True
    )
def DisplayPlaybookNodeData(data, is_open):
    if data:
        # extract module_id from node label
        if data['label'] != "None":
            module_id = data['label'].split(":")[0]
        else:
            raise PreventUpdate

        # extract module information
        try:
            # if module id is number - return time gap
            int(module_id)
            return [html.B(f"Time Gap : {module_id} seconds")], True
        except:
            return DisplayTechniqueInfo(module_id), not is_open
    else:
        raise PreventUpdate
        
'''C029 - Callback to display playbook node data on hover'''
@app.callback(
        Output(component_id = "playbook-node-data-div", component_property = "children", allow_duplicate= True),
        Input(component_id = "auto-attack-sequence-cytoscape-nodes", component_property = "mouseoverNodeData"), 
        prevent_initial_call=True
    )
def DisplayPlaybookNodeData(data):
    display_elements = []
    if data:
        # extract module_id from node label
        if data['label'] != "None":
            module_id = data['label'].split(":")[0]
        else:
            raise PreventUpdate

        # extract module information
        try:
            # if module id is number - return time gap
            int(module_id)
            display_elements.append(html.B(f"Time Gap : {module_id} seconds"))
            return display_elements
        except:
            # if halberd module_if - return the module info
            module_info = EnrichNodeInfo(module_id)

            # display module name
            module_name = module_info['Name']
            display_elements.append(html.B("Module Name : "))
            display_elements.append(html.A(module_name))
            display_elements.append(html.Br())
            
            module_attack_surface = module_info['AttackSurface']
            display_elements.append(html.B("Attack Surface : "))
            display_elements.append(html.A(module_attack_surface))
            display_elements.append(html.Br())

            # display module mitre info
            if module_info['References']['MITRE']:
                module_mitre_technique_id = module_info['References']['MITRE']

                for mitre_technique in module_mitre_technique_id:
                    tactics = module_mitre_technique_id[mitre_technique]['Tactic']
                    technique_name = module_mitre_technique_id[mitre_technique]['Technique']
                    sub_technique_name = module_mitre_technique_id[mitre_technique]['SubTechnique']
                    
                    display_elements.append(html.B("Tactics : "))
                    display_elements.append(html.A(tactics))
                    display_elements.append(html.Br())

                    display_elements.append(html.B("Technique : "))
                    if sub_technique_name:
                        display_elements.append(html.A(f"{technique_name} : {sub_technique_name}"))
                        
                    else:
                        display_elements.append(html.A(technique_name))
                    display_elements.append(html.Br())

            # display azure threat research matrix info
            if module_info['References']['AzureThreatResearchMatrix'][0]:
                module_azure_trm = module_info['References']['AzureThreatResearchMatrix']
                display_elements.append(html.B("Module Azure TRM Info : "))
                display_elements.append(html.A(str(module_azure_trm)))
                display_elements.append(html.Br())
            return display_elements
    else:
        raise PreventUpdate

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
def toggle_modal(n1, n2, n3, is_open):
    if n1 or n2 or n3:
        return not is_open
    return is_open

'''C031 - Callback to generate playbook options in Automator - Attack Playbook dropdown'''
@app.callback(Output(component_id = "automator-pb-selector-dropdown", component_property = "options"), Input(component_id = "automator-pb-selector-dropdown", component_property = "title"))
def GenerateDropdownOptionsCallBack(title):
    if title == None:
        playbook_dropdown_option = []    
        for pb in GetAllPlaybooks():
            
            playbook_dropdown_option.append(
                {
                    "label": html.Div([Playbook(pb).name], style={'font-size': 20}, className="text-dark"),
                    "value": Playbook(pb).name,
                }
            )
        return playbook_dropdown_option
    
'''C032 - Callback to delete playbook'''
@app.callback(
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), 
        Input(component_id = "delete-pb-button", component_property = "n_clicks"), 
        State(component_id = "automator-pb-selector-dropdown", component_property = "value"), 
        prevent_initial_call=True)
def ExportAttackPlaybook(n_clicks, playbook_name):
    if n_clicks == 0:
        raise PreventUpdate
        
    # if no playbook is selected, send notification
    if playbook_name == None:
        return True, "No Playbook Selected to Delete"
    
    # get the selected playbook file location
    for pb in GetAllPlaybooks():
        pb_config = Playbook(pb)
        if  pb_config.name == playbook_name:
            playbook_file = pb_config.file

    try:
        os.remove(playbook_file)
        return True, "Playbook Deleted"
    except Exception as e:
        return True, "Failed to Delete Playbook"

'''C033 - Callback to open modal and display technique information from home techniques matrix'''
@app.callback(
    Output("app-technique-info-display-modal", "is_open", allow_duplicate=True),
    Output("app-technique-info-display-modal-body", "children", allow_duplicate = True),
    Input({"type": "technique", "index": dash.ALL}, "n_clicks"),
    State("app-technique-info-display-modal", "is_open"),
    prevent_initial_call=True
)
def ToggleAppModalFromHomeMatrix(n_clicks, is_open):
    # prevent call back on page load
    if any(item is not None for item in n_clicks):
        if not dash.callback_context.triggered:
            return is_open, ""
        
        # extract technique id
        triggered_id = dash.callback_context.triggered[0]["prop_id"]
        technique_id = eval(triggered_id.split(".")[0])["index"]

        # generate technique information
        technique_details = DisplayTechniqueInfo(technique_id)
        
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
def CloseAppModal(n_clicks, is_open):
    if n_clicks:
        return False
    return is_open

'''C035 - Callback to download report'''
@app.callback(
    Output("app-download-sink", "data", allow_duplicate=True),
    Input("generate-report-button", "n_clicks"),
    prevent_initial_call=True,
)
def DownloadReport(n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    return dcc.send_file(TRACE_LOG_FILE)

'''C036 - Callback to display entity map node information'''
@app.callback(
    Output("entity-map-node-info-div", "children"),
    Input("entity-detection-cytoscape-nodes", "tapNodeData"),
)
def DisplayEntityMapNodeInfo(data):
    if not data:
        return "Click on a node to see more information."
    return f"Selected Node: {data['label']}"
    
'''C037 - Callback to display playbook information in playook information modal'''
@app.callback(Output(component_id = "automator-playbook-info-display-modal", component_property = "is_open", allow_duplicate=True),
              Output("automator-playbook-info-display-modal-body", "children", allow_duplicate = True), 
              Input(component_id= "pb-view-details-button", component_property= "n_clicks"),
              State(component_id = "automator-pb-selector-dropdown", component_property = "value"), 
              State("automator-playbook-info-display-modal", "is_open"),
              prevent_initial_call=True
)
def ShowPlaybookInfo(n_clicks, selected_pb, is_open):
    if n_clicks == 0:
        raise PreventUpdate
    
    return not is_open, DisplayPlaybookInfo(selected_pb)

'''C038 - Callback to close the playbook information modal'''
@app.callback(
    Output("automator-playbook-info-display-modal", "is_open", allow_duplicate=True),
    Input("close-automator-playbook-info-display-modal", "n_clicks"),
    State("automator-playbook-info-display-modal", "is_open"),
    prevent_initial_call=True
)
def ClosePbInfoModal(n_clicks, is_open):
    if n_clicks:
        return False
    return is_open

'''C039 - Callback to download technique response data'''
@app.callback(
    Output("app-download-sink", "data", allow_duplicate=True),
    Input("download-technique-response-button", "n_clicks"),
    State("technique-output-memory-store", "data"),
    prevent_initial_call=True
)
def DownloadTechniqueRawResponse(n_clicks, data):
    if n_clicks is None or data is None:
        raise PreventUpdate
    
    # create a file in the outputs directory
    execution_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    output_filepath = f"./output/Response_Export_{execution_time}.txt"
    with open(output_filepath, "w") as f:
        f.write(str(data))
    
    # download response file
    return dcc.send_file(output_filepath)

if __name__ == '__main__':
    # initialize primary app files
    InitializationCheck()
    TacticMapGenerator()
    TechniqueMapGenerator()
    # start application
    app.run_server(debug = True)