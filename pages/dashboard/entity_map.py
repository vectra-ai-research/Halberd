'''
Dashboard Name: Entity Map
Dashboard Description: Displays an interactive graph of access & privilege of an entra ID entity. Content is dynamically generated 
'''
from dash import html, dcc
import dash_bootstrap_components as dbc
from core.entra.entra_token_manager import EntraTokenManager
from core.entra.graph_request import GraphRequest
import dash_cytoscape as cyto

# generate entity map
def GenerateEntityMappingGraph(map_layout = 'cose', filter_category = None):
    manager = EntraTokenManager()
    active_token = manager.get_active_token()
    active_token_info = manager.decode_jwt_token(active_token)
    access_type = active_token_info['Entity Type']
    if access_type == "user":
        username,displayname, user_object_id = GetUserInfo()
        categories = ['Groups', 'Roles', 'Applications', 'Data Repos']

        elements = []
        n = 1

        # Create primary node as the selected entity
        elements.append({'data': {'id': '0', 'label': displayname}, 'classes': 'entity'})
        
        # Dynamically create nodes for each detection on the entity
        for category in categories:
            if filter_category and category != filter_category:
                continue
            # Create a node for each category on the entity
            elements.append({'data': {'id': str(n), 'label': category}, 'classes': 'category'})
            # Create an edge between entity and each detection
            elements.append({'data': {'source': '0', 'target': str(n)}})
            n += 1
            if category == 'Groups':
                if ListJoinedTeams() != None:
                    sub_node_n = n-1
                    teams = ListJoinedTeams()
                    for team in teams:
                        elements.append({'data': {'id': str(n), 'label': team}, 'classes': 'end_node'})
                        # Create an edge between entity and each detection
                        elements.append({'data': {'source': str(sub_node_n), 'target': str(n)}})
                        n += 1
            if category == 'Roles':   
                if ListObjectsMemberOf() != None:
                    sub_node_n = n-1
                    group_list, roles_list, others_list = ListObjectsMemberOf()
                    for role in roles_list:
                        elements.append({'data': {'id': str(n), 'label': role}, 'classes': 'end_node'})
                        # Create an edge between entity and each detection
                        elements.append({'data': {'source': str(sub_node_n), 'target': str(n)}})
                        n += 1

            if category == 'Applications':
                if ListAppRoleAssignments() != None:
                    sub_node_n = n-1
                    applications = ListAppRoleAssignments()
                    for application in applications:
                        elements.append({'data': {'id': str(n), 'label': application}, 'classes': 'end_node'})
                        # Create an edge between entity and each detection
                        elements.append({'data': {'source': str(sub_node_n), 'target': str(n)}})
                        n += 1

            if category == 'Data Repos':
                if ListDrives() != None:
                    sub_node_n = n-1
                    repos = ListDrives()
                    for repo in repos:
                        elements.append({'data': {'id': str(n), 'label': repo}, 'classes': 'end_node'})
                        # Create an edge between entity and each detection
                        elements.append({'data': {'source': str(sub_node_n), 'target': str(n)}})
                        n += 1
                

        # Return the network graph
        return cyto.Cytoscape(
            id='entity-detection-cytoscape-nodes',
            layout={'name': map_layout},
            style={'width': '100vw', 'height': '100vh'},
            elements= elements,
            stylesheet=[
                # Add styles for the graph here
                {
                    'selector': 'node',
                    'style': {
                        'label': 'data(label)',
                        'background-color': '#ff0000',
                        'color': '#fff',
                        'text-halign': 'center',
                        'text-valign': 'center',
                        'text-wrap': 'wrap',
                        'text-max-width': '30px',
                        'font-size': '5px',
                    }
                },
                {
                    'selector': '.entity',
                    'style': {
                        'label': 'data(label)',
                        'background-color': '#0074D9',
                        'color': '#fff',
                        'width': '40px',
                        'height': '40px',
                        'text-halign': 'center',
                        'text-valign': 'center',
                        'text-wrap': 'wrap',
                        'text-max-width': '30px',
                        'shape': 'circle',
                    }
                },
                {
                    'selector': 'edge',
                    'style': {
                        'curve-style': 'bezier',
                        'target-arrow-shape': 'triangle',
                        'line-color': '#AAAAAA',
                        'target-arrow-color': '#AAAAAA',
                    }
                },
                {
                    'selector': '.end_node',
                    'style': {
                        'label': 'data(label)',
                        'background-color': '#000000',
                        'color': '#fff',
                        'width': '40px',
                        'height': '40px',
                        'text-halign': 'center',
                        'text-valign': 'center',
                        'text-wrap': 'wrap',
                        'text-max-width': '30px',
                        'shape': 'square',
                    }
                },
                {
                    'selector': ':selected',
                    'style': {
                        'border-width': '3px',
                        'border-color': '#AAAAAA',
                    }
                }
            ]
            )
    else:
        return html.Div([
            html.Br(),
            html.B("Requires a delegated access token!!!", style={'color':'Red'}),
            html.Br(),
            html.Br(),
            html.B("Select a delegated access token on 'Access' page")
            ])

# create page layout
page_layout = html.Div([
    dbc.Row([
        # input fields for map type
        dbc.Col([
            dbc.Select(
                id='map-layout-select',
                options=[
                    {'label': 'Circular', 'value': 'circle'},
                    {'label': 'Hierarchical', 'value': 'breadthfirst'},
                    {'label': 'Force-directed', 'value': 'cose'},
                ],
                value='cose',
                className="mb-3"
            ),
        ],width=3),
        # input fields for filter
        dbc.Col([
            dbc.Select(
                id='filter-select',
                options=[
                    {'label': 'All', 'value': 'all'},
                    {'label': 'Groups', 'value': 'Groups'},
                    {'label': 'Roles', 'value': 'Roles'},
                    {'label': 'Applications', 'value': 'Applications'},
                    {'label': 'Data Repos', 'value': 'Data Repos'},
                ],
                value='all',
                className="mb-3"
            ),
        ],width=3),
        # generate map button
        dbc.Col([
            dbc.Button("Generate Entity Map", id="generate-entity-map-button", color="danger", className="mb-3"),
        ], width=3),
        # export result button
        dbc.Col(
            dbc.Button("Export Results", color="primary", className="mb-3", id="export-button"),
            width=3
        )
    ]),
    
    dbc.Col([
        dbc.Card([
            dbc.CardHeader("Entity Map", className="bg-dark text-light"),
            dbc.CardBody([
                dcc.Loading(
                    id="entity-map-loading",
                    type="default",
                    children=html.Div(id="entity-map-display-div", style={"height": "60vh", "overflow": "auto"})
                )
            ], className="bg-dark")
        ], className="mb-4 border-secondary"),

        # display node info
        dbc.Card([
            dbc.CardHeader("Node Info", className="bg-dark text-light"),
            dbc.CardBody([
                html.Div(id="entity-map-node-info-div", className="mt-3 text-light"),
            ], className="bg-dark")
        ], className="mb-4 border-secondary")
    ]),
], className="bg-dark p-4")

def GetUserInfo():
    endpoint_url = "https://graph.microsoft.com/v1.0/me"

    user_info = GraphRequest().get(url = endpoint_url)
    user_name = user_info['userPrincipalName']
    display_name = user_info['displayName']
    user_object_id = user_info['id']
    return user_name, display_name, user_object_id

def ListJoinedTeams():
    try:
        endpoint_url = "https://graph.microsoft.com/v1.0/me/joinedTeams"

        joined_teams_list = GraphRequest().get(url = endpoint_url)
        
        output_list=[]
        for teams in joined_teams_list:
            output_list.append(teams['displayName'])

        return output_list
    except:
        return None
    
def ListObjectsMemberOf():
    try:
        username,displayname, user_object_id = GetUserInfo()

        endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_object_id}/memberOf"

        member_objects_list = GraphRequest().get(url = endpoint_url)

        group_list = []
        roles_list = []
        others_list = []
        for object in member_objects_list:
            if object["@odata.type"] == "#microsoft.graph.directoryRole":
                roles_list.append(object["displayName"])
            elif object["@odata.type"] == "#microsoft.graph.group":
                group_list.append(object["displayName"])
            else:
                others_list.append(object["displayName"])

        return group_list, roles_list, others_list
    except:
        return None
    
def ListAppRoleAssignments():
    try:
        username,displayname, user_object_id = GetUserInfo()
        endpoint_url = f"https://graph.microsoft.com/v1.0/users/{user_object_id}/appRoleAssignments"

        app_role_assignments_list = GraphRequest().get(url = endpoint_url)
        output_list = []

        for app_role in app_role_assignments_list:
            output_list.append(app_role['resourceDisplayName'])

        return output_list
    except:
        return None
    
def ListDrives():
    try:
        endpoint_url = "https://graph.microsoft.com/v1.0/me/drive"

        drives_list = GraphRequest().get(url = endpoint_url)

        output_list = []
        output_list.append(f"{drives_list['name']} : {drives_list['webUrl']}")

        return output_list
    except:
        return None