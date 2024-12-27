import dash_bootstrap_components as dbc
from dash import dcc,html
from core.entra.graph_request import GraphRequest

# find role ID
def FindRole(role_name):
    role_endpoint_url = 'https://graph.microsoft.com/v1.0/directoryRoles'
    params = {
        '$filter': f'displayName eq \'{role_name}\''
    }

    role_recon_response = GraphRequest().get(role_endpoint_url, params=params)
    if 'error' in role_recon_response:
        # graph request failed
        return None

    # get role_id and role_display_name
    for role in role_recon_response:
        role_name = role['displayName']
        role_id = role['id']
        role_template_id = role['roleTemplateId']
        role_description = role['description']

    return role_name, role_id, role_template_id, role_description

def ReconRoleInfo(role_id):
    pass


# find members of role
def ReconRoleMembers(role_template_id):
    graph_url = f"https://graph.microsoft.com/v1.0/directoryRoles(roleTemplateId='{role_template_id}')/members"
    raw_response = GraphRequest().get(graph_url)

    if 'error' in raw_response:
        # graph request failed
        return None
    
    member_count= len(raw_response)
    
    table_header = [
        html.Thead(html.Tr([html.Th("User"), html.Th("UPN"), html.Th("User Object ID")]))
    ]

    table_entries = []
    for member in raw_response:
        table_entries.append(
            html.Tr([html.Td(member['displayName']), html.Td(member['userPrincipalName']), html.Td(member['id'])])
        )

    table_body = [html.Tbody(table_entries)]
    table_content = table_header + table_body

    return member_count, dbc.Table(table_content, bordered=True, dark=True, hover=True)

# define dashboard layout
page_layout = html.Div([
    html.H4("Enter Role Name"),
    dbc.Row([
        dbc.Col(
            dbc.Input(
                type = "text",
                placeholder = "Security Administrator",
                debounce = True,
                id = "role-recon-input",
                className="bg-halberd-dark border halberd-text halberd-input mb-3",
            ),
            width=6
        ),
        dbc.Col([
            dbc.Button("Run Recon", id="role-recon-start-button", n_clicks=0, className="me-3 halberd-button"),
            dbc.Button("Export Results", className="halberd-button-secondary", id="export-button"),
        ], width=6)
    ], className= "mb-3"),
    html.H2("Role Name"),
    dcc.Loading(
        id="role-name-recon-loading",
        type="default",
        children=html.Div(id="role-name-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
    ),
    html.Br(),
    html.H2("Role Template ID"),
    dcc.Loading(
        id="role-template-id-recon-loading",
        type="default",
        children=html.Div(id="role-template-id-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
    ),
    html.Br(),
    html.H2("Role ID"),
    dcc.Loading(
        id="role-id-recon-loading",
        type="default",
        children=html.Div(id="role-id-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
    ),
    html.Br(),
    html.H2("Role Members Count"),
    dcc.Loading(
        id="role-member-count-recon-loading",
        type="default",
        children=html.Div(id="role-member-count-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
    ),
    html.Br(),
    html.H2("Role Members"),
    dcc.Loading(
        id="role-member-recon-loading",
        type="default",
        children=html.Div(id="role-member-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"30vh", 'overflow': 'auto'})
    ),
    html.Br(),
    html.H2("Role Description"),
    dcc.Loading(
        id="role-description-recon-loading",
        type="default",
        children=html.Div(id="role-description-recon-div", children = "-", style={"border":"1px solid #ccc", "padding-top": "10px", "padding-bottom": "10px", "padding-right": "10px", "padding-left": "10px", "height":"4vh", 'overflow': 'auto'})
    ),
    html.Br(),
],
style={ "height": "100vh", "padding-top": "20px", "padding-bottom": "20px", "padding-right": "20px", "padding-left": "20px"},
className="halberd-text"
)