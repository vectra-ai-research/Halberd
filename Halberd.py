#!/usr/bin/env python3
import json
import dash
import dash_daq as daq
import dash_bootstrap_components as dbc
from dash import dcc, html, Patch, ALL
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
from core.EntraAuthFunctions import FetchSelectedToken, ExtractTokenInfo, SetSelectedToken, FetchAllTokens
from pages.dashboard.entity_map import GenerateEntityMappingGraph
from core.Local import InitializationCheck
from core.TabContentGenerator import *
from core.TechniqueOptionsGenerator import *
from core.TacticMapGenerator import *
from core.TechniqueInfoGenerator import *
from core.TechniqueMapGenerator import *
from core.TechniqueExecutor import *
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
    config_div_display.append(html.Div([
            dbc.Button("Execute Technique", id="technique-execute-button", n_clicks=0, color="danger"),
            html.Br(),
            dbc.Button("About Technique", id="technique-info-display-button", n_clicks=0, color="danger")
        ], className="d-grid col-6 mx-auto"))
    
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
    
    return config_div_display

'''C005 - Attack Execution Callback - Execute Technique'''
@app.callback(Output(component_id = "execution-output-div", component_property = "children"), Output(component_id = "app-notification", component_property = "is_open"), Output(component_id = "app-notification", component_property = "children"), Input(component_id= "technique-execute-button", component_property= "n_clicks"), State(component_id = "attack-options-radio", component_property = "value"), State({"type": "technique-config-display", "index": ALL}, "value"), State({"type": "technique-config-display-file-upload", "index": ALL}, "contents"), prevent_initial_call = True)
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


'''C007 - Callback to display available techniques in radio list'''
@app.callback(Output(component_id = "technique-info-offcanvas", component_property = "is_open"), Input(component_id = "attack-options-radio", component_property = "value"), Input(component_id= "technique-info-display-button", component_property= "n_clicks"),[State("technique-info-offcanvas", "is_open")], prevent_initial_call=True)
def DisplayAttackTechniqueConfig(t_id, n_clicks, is_open):
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


if __name__ == '__main__':
    # initialize primary app files
    InitializationCheck()
    TacticMapGenerator()
    TechniqueMapGenerator()

    # start application
    app.run_server(debug = True)