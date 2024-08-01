#!/usr/bin/env python3
import json
import dash
import dash_daq as daq
import dash_bootstrap_components as dbc
from dash import dcc, html, Patch, ALL
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
from core.EntraAuthFunctions import FetchSelectedToken, ExtractTokenInfo, SetSelectedToken, FetchAllTokens
from core.AzureFunctions import GetCurrentSubscriptionAccessInfo, GetAccountSubscriptionList, SetDefaultSubscription
from pages.dashboard.entity_map import GenerateEntityMappingGraph
from core.Local import InitializationCheck
from core.TabContentGenerator import *
from core.TechniqueOptionsGenerator import *
from core.TacticMapGenerator import *
from core.TechniqueInfoGenerator import *
from core.TechniqueMapGenerator import *
from core.TechniqueExecutor import *
from core.AttackPlaybookVisualizer import AttackSequenceVizGenerator, EnrichNodeInfo
from core.Automator import ExecutePlaybook, AddNewSchedule, Playbook, GetAllPlaybooks, ImportPlaybook, CreateNewPlaybook
import datetime
import boto3

# Create Application
app = dash.Dash(__name__,  external_stylesheets=[dbc.themes.LUX],title='Halberd', update_title='Loading...', suppress_callback_exceptions=True)

# Navigation bar layout
navbar = dbc.NavbarSimple(
    children=[
        dbc.NavItem(dbc.NavLink("Access", href="/access")),
        dbc.NavItem(dbc.NavLink("Attack", href="/attack")),
        dbc.NavItem(dbc.NavLink("Recon", href="/recon")),
        dbc.NavItem(dbc.NavLink("Trace", href="/attack-trace")),
        dbc.NavItem(dbc.NavLink("Automator", href="/automator")),
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
                config_div_elements.append(daq.BooleanSwitch(id = {"type": "technique-config-display", "index": "input"}, on=False))
            
            if config_field['element_type'] == "dcc.Upload":
                config_div_elements.append(dcc.Upload(id = {"type": "technique-config-display-file-upload", "index": "file"}, children=html.Div([html.A('Drag and Drop or Select a File')]), style={'width': '100%', 'height': '60px', 'lineHeight': '60px', 'borderWidth': '1px', 'borderStyle': 'dashed', 'borderRadius': '5px', 'textAlign': 'center', 'margin': '10px'}))

            if config_field['element_type'] == "dcc.Input":
                config_div_elements.append(dbc.Input(
                    type = config_field['type'],
                    placeholder = config_field['placeholder'],
                    debounce = True,
                    id = {"type": "technique-config-display", "index": "input"},
                    class_name="text-dark"
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
            dbc.Button("About Technique", id="technique-info-display-button", n_clicks=0, color="danger"),
            html.Br(),
            dbc.Button("Add to Playbook", id="open-add-to-playbook-modal-button", n_clicks=0, color="danger")
        ], style={'display': 'flex', 'justify-content': 'center', 'gap': '10px'})
    )
    
    config_div_display.append(
        html.Div(id='attack-technique-sink-hidden-div', style={'display':'none'}),
    )
    
    config_div_display.append(
        dbc.Offcanvas(
            TechniqueRecordInfo(t_id),
            id="technique-info-offcanvas",
            title="Attack Technique Info",
            placement = "end",
            is_open=False,
        )
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
@app.callback(Output(component_id = "execution-output-div", component_property = "children"), Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), Input(component_id= "technique-execute-button", component_property= "n_clicks"), State(component_id = "attack-options-radio", component_property = "value"), State({"type": "technique-config-display", "index": ALL}, "value"), State({"type": "technique-config-display-file-upload", "index": ALL}, "contents"), prevent_initial_call = True)
def ExecuteTechnique(n_clicks, t_id, values, file_content):
    if n_clicks == 0:
        raise PreventUpdate
    
    if file_content:
        return TechniqueOutput(t_id, values, file_content), True, "Technique Executed"
    else:
        return TechniqueOutput(t_id, values), True, "Technique Executed"

'''C006 - Entity Map - Generate Map'''
@app.callback(Output(component_id = "entity-map-display-div", component_property = "children"), Input(component_id = "generate-entity-map-button", component_property = "n_clicks"), prevent_initial_call=True)
def GenerateEntityMap(n_clicks):
    if n_clicks:
        return GenerateEntityMappingGraph()


'''C007 - Callback to open/close Technique Info off canvas'''
@app.callback(Output(component_id = "technique-info-offcanvas", component_property = "is_open"), Input(component_id= "technique-info-display-button", component_property= "n_clicks"),[State("technique-info-offcanvas", "is_open")], prevent_initial_call=True)
def DisplayAttackTechniqueConfig(n_clicks, is_open):
    if n_clicks == 0:
        raise PreventUpdate
    
    return not is_open


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
    Output("download-trace-logs", "data"),
    Input("download-trace-logs-button", "n_clicks"),
    prevent_initial_call=True,
)
def DownloadTraceLogs(n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    return dcc.send_file("./Local/Trace_Log.csv")

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
                if datetime.datetime.strptime(access_info['Access Exp'], '%Y-%m-%dT%H:%M:%SZ') < datetime.datetime.utcnow():
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
                if datetime.datetime.strptime(access_info['Access Exp'], '%Y-%m-%dT%H:%M:%SZ') < datetime.datetime.utcnow():
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
        for pb in GetAllPlaybooks():
            pb_config = Playbook(pb)
            if  pb_config.name == selected_pb:
                break
        display_elements = []

        # display playbook name
        display_elements.append(html.B("Plabook Name : "))
        display_elements.append(html.A(pb_config.name))
        display_elements.append(html.Br())

        # display playbook description
        display_elements.append(html.B("Plabook Description : "))
        display_elements.append(html.A(pb_config.description))
        display_elements.append(html.Br())

        # display playbook author
        display_elements.append(html.B("Plabook Author : "))
        display_elements.append(html.A(pb_config.author))
        display_elements.append(html.Br())

        # display playbook creation date
        display_elements.append(html.B("Plabook Creation Date : "))
        display_elements.append(html.A(pb_config.creation_date))
        display_elements.append(html.Br())

        # display playbook references
        display_elements.append(html.B("Plabook References : "))
        if pb_config.references: 
            if type(pb_config.references) == list:
                for ref in pb_config.references:
                    display_elements.append(html.Br())
                    display_elements.append(html.A(ref, href=ref, target='_blank'))
                    
            else:
                display_elements.append(html.A(pb_config.references))
        else:
            display_elements.append(html.A("N/A"))

        display_elements.append(html.Br())

        return AttackSequenceVizGenerator(selected_pb), display_elements 
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
    return True, "No Playbook Selected to Execute", False

'''C023 - Callback to export playbook'''
@app.callback(Output(component_id = "download-pb-config-file", component_property = "data"), Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), Input(component_id = "automator-pb-selector-dropdown", component_property = "value"), Input(component_id = "export-pb-button", component_property = "n_clicks"), prevent_initial_call=True)
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
@app.callback(Output(component_id = "hidden-div", component_property = "children"), Input(component_id = 'upload-playbook', component_property = 'contents'), State(component_id = 'upload-playbook', component_property = 'filename'))
def UploadHalberdPlaybook(contents, filename):
    ImportPlaybook(contents, filename)
    return None

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
        Input(component_id = "pb-name-input", component_property = "value"), 
        Input(component_id = "pb-desc-input", component_property = "value"), 
        Input(component_id = "pb-author-input", component_property = "value"), 
        Input(component_id = "pb-refs-input", component_property = "value"), 
        Input(component_id = "create-playbook-button", component_property = "n_clicks"), prevent_initial_call=True
    )
def CreateNewPlaybookCallback(pb_name, pb_desc, pb_author, pb_references, n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    
    return CreateNewPlaybook(pb_name, pb_desc, pb_author, pb_references), False

'''C028 - Callback to display playbook node data'''
@app.callback(
        Output(component_id = "pb-technique-info-offcanvas", component_property = "children"),
        Output(component_id = "pb-technique-info-offcanvas", component_property = "is_open"),
        Input(component_id = "auto-attack-sequence-cytoscape-nodes", component_property = "tapNodeData"),
        [State(component_id = "pb-technique-info-offcanvas", component_property = "is_open")], 
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
            return TechniqueRecordInfo(module_id), not is_open
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
            
            # display module description
            # if module_info['Description']:
            #     module_desc = module_info['Description']
            #     display_elements.append(html.B("Module Description : "))
            #     display_elements.append(html.A(module_desc))
            #     display_elements.append(html.Br())
            
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

if __name__ == '__main__':
    # initialize primary app files
    InitializationCheck()
    TacticMapGenerator()
    TechniqueMapGenerator()

    # start application
    app.run_server(debug = True)