import dash_bootstrap_components as dbc
from dash import dcc,html
from core.GraphFunctions import graph_get_request

# find role ID
def FindUser(user_string):
    role_endpoint_url = 'https://graph.microsoft.com/v1.0/users'
    params = {
        '$filter': f'userPrincipalName eq \'{user_string}\''
    }

    user_recon_response = graph_get_request(role_endpoint_url, params=params)
    if 'error' in user_recon_response:
        # graph request failed
        return None, None, None, None, None, None, None

    # get role_id and role_display_name
    for user in user_recon_response:
        user_id = user['id']
        user_upn = user['userPrincipalName']
        user_display_name = user['displayName']
        user_job_title = user['jobTitle']
        user_off_location = user['officeLocation']
        user_phone = user['mobilePhone']
        user_mail = user['mail']
        

    return user_id, user_upn, user_display_name, user_mail, user_job_title, user_off_location, user_phone

# find users membership
def ReconUserMemberships(user_id):
    graph_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf"
    raw_response = graph_get_request(graph_url)

    if 'error' in raw_response:
        # graph request failed
        return None

    group_list = []
    roles_list = []
    others_list = []
    
    for object in raw_response:
        if object["@odata.type"] == "#microsoft.graph.directoryRole":
            roles_list.append(object["displayName"])
        elif object["@odata.type"] == "#microsoft.graph.group":
            group_list.append(object["displayName"])
        else:
            others_list.append(object["displayName"])
    
    groups_count = len(group_list)
    role_count = len(roles_list)
    
    table_header = [
        html.Thead(html.Tr([html.Th(html.Div("Group", className="danger"))]))
    ]

    table_entries = []
    for group in group_list:
        table_entries.append(
            html.Tr([html.Td(group)])
        )

    table_body = [html.Tbody(table_entries)]
    group_table_content = table_header + table_body

    table_header = [
        html.Thead(html.Tr([html.Th("Role")]))
    ]

    table_entries = []
    for role in roles_list:
        table_entries.append(
            html.Tr([html.Td(role)])
        )

    table_body = [html.Tbody(table_entries)]
    role_table_content = table_header + table_body

    return groups_count, role_count, dbc.Table(group_table_content, bordered=True, responsive=True, dark=True, hover=True), dbc.Table(role_table_content, bordered=True, responsive=True, dark=True, hover=True)

# find users assigned applications
def ReconUserAssignedApps(user_id):
    app_endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/appRoleAssignments"
    raw_response = graph_get_request(app_endpoint_url)
    if 'error' in raw_response:
        # graph request failed
        return None
    
    app_assigned_count = len(raw_response)
    
    table_header = [
        html.Thead(html.Tr([html.Th("Applications")]))
    ]
    table_entries = []
    for app in raw_response:
        table_entries.append(
            html.Tr([html.Td(app['resourceDisplayName'])])
        )
    
    table_body = [html.Tbody(table_entries)]
    app_table_content = table_header + table_body

    return app_assigned_count, dbc.Table(app_table_content, bordered=True, responsive=True, dark=True, hover=True)


# define dashboard layout
page_layout = html.Div([
    html.H4("Enter User Info"),
    dbc.Row([
        dbc.Col(
            dbc.Input(
                type = "text",
                placeholder = "John Doe",
                debounce = True,
                id = "user-recon-input",
                class_name="text-dark mb-3",
            ),
            width=6
        ),
        dbc.Col(
            dbc.Button("Recon", id="user-recon-start-button", n_clicks=0, color="danger", className="mb-3"),
            width=3
        ),
        dbc.Col(
            dbc.Button("Export Results", color="primary", className="mb-3", id="export-button"),
            width=3
        )
    ]),
    html.Br(),
    html.H2("Name"),
    dcc.Loading(
        id="user-displayname-recon-loading",
        type="default",
        children=html.Div(id="user-displayname-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
    ),
    html.Br(),
    dbc.Row([
        dbc.Col([
            html.H2("Object ID"),
            dcc.Loading(
                id="user-id-recon-loading",
                type="default",
                children=html.Div(id="user-id-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
            ),
        ]),
        dbc.Col([
            html.H2("UPN"),
            dcc.Loading(
                id="user-upn-recon-loading",
                type="default",
                children=html.Div(id="user-upn-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
            ),
        ]),
        dbc.Col([
            html.H2("Mailbox"),
            dcc.Loading(
                id="user-mail-recon-loading",
                type="default",
                children=html.Div(id="user-mail-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
            )
        ])
    ]),
    html.Br(),
    dbc.Row([
        dbc.Col([
            html.H2("Job Title"),
            dcc.Loading(
                id="user-job-title-recon-loading",
                type="default",
                children=html.Div(id="user-job-title-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
            )
        ]),
        dbc.Col([
            html.H2("Job Location"),
            dcc.Loading(
                id="user-location-recon-loading",
                type="default",
                children=html.Div(id="user-location-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
            )
        ]),
        dbc.Col([
            html.H2("Phone"),
            dcc.Loading(
                id="user-phone-recon-loading",
                type="default",
                children=html.Div(id="user-phone-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
            )
        ])
    ]),
    html.Br(),
    html.H2("Number of Group Memberships"),
    dcc.Loading(
        id="user-group-count-recon-loading",
        type="default",
        children=html.Div(id="user-group-count-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
    ),
    html.Br(),
    html.H2("Group Memberships"),
    dcc.Loading(
        id="user-groups-recon-loading",
        type="default",
        children=html.Div(id="user-groups-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"30vh", 'overflow': 'auto'})
    ),
    html.Br(),
    html.H2("Number of Roles Assigned"),
    dcc.Loading(
        id="user-role-count-recon-loading",
        type="default",
        children=html.Div(id="user-role-count-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
    ),
    html.Br(),
    html.H2("Roles Assigned"),
    dcc.Loading(
        id="user-roles-recon-loading",
        type="default",
        children=html.Div(id="user-roles-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"30vh", 'overflow': 'auto'})
    ),
    html.Br(),
    html.Br(),
    html.H2("Number of Applications Assigned"),
    dcc.Loading(
        id="user-app-count-recon-loading",
        type="default",
        children=html.Div(id="user-app-count-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
    ),
    html.Br(),
    html.H2("Applications Assigned"),
    dcc.Loading(
        id="user-app-recon-loading",
        type="default",
        children=html.Div(id="user-app-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"30vh", 'overflow': 'auto'})
    ),
    html.Br(),
],
style={ "height": "100vh", "padding-top": "20px", "padding-bottom": "20px", "padding-right": "20px", "padding-left": "20px"}
)