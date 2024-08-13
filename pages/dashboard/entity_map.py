'''
Dashboard Name: Entity Map
Dashboard Description: Displays an interactive graph of access & privilege of an entra ID entity. Content is dynamically generated 
'''
from dash import html, dcc
import dash_bootstrap_components as dbc
from Techniques.EntraID.EntraPrimaryFunctions import GetUserInfo, ListJoinedTeams, ListObjectsMemberOf, ListAppRoleAssignments, ListDrives
from core.EntraAuthFunctions import FetchSelectedToken, ExtractTokenInfo
import dash_cytoscape as cyto

# generate entity map
def GenerateEntityMappingGraph(map_layout = 'cose', filter_category = None):
    active_token = FetchSelectedToken()
    active_token_info = ExtractTokenInfo(active_token)
    access_type = active_token_info['Entity Type']
    if access_type == "user":
        username,displayname, user_object_id = GetUserInfo()
        categories = ['Groups', 'Roles', 'Applications', 'Data Repos']

        elements = []
        n = 1

        #Create primary node as the selected entity
        elements.append({'data': {'id': '0', 'label': displayname}, 'classes': 'entity'})
        
        #Dynamically create nodes for each detection on the entity
        for category in categories:
            if filter_category and category != filter_category:
                continue
            #create a node for each category on the entity
            elements.append({'data': {'id': str(n), 'label': category}, 'classes': 'category'})
            #create an edge between entity and each detection
            elements.append({'data': {'source': '0', 'target': str(n)}})
            n += 1
            if category == 'Groups':
                if ListJoinedTeams() != None:
                    sub_node_n = n-1
                    teams = ListJoinedTeams()
                    for team in teams:
                        elements.append({'data': {'id': str(n), 'label': team}, 'classes': 'end_node'})
                        #create an edge between entity and each detection
                        elements.append({'data': {'source': str(sub_node_n), 'target': str(n)}})
                        n += 1
            if category == 'Roles':   
                if ListObjectsMemberOf() != None:
                    sub_node_n = n-1
                    group_list, roles_list, others_list = ListObjectsMemberOf()
                    for role in roles_list:
                        elements.append({'data': {'id': str(n), 'label': role}, 'classes': 'end_node'})
                        #create an edge between entity and each detection
                        elements.append({'data': {'source': str(sub_node_n), 'target': str(n)}})
                        n += 1

            if category == 'Applications':
                if ListAppRoleAssignments() != None:
                    sub_node_n = n-1
                    applications = ListAppRoleAssignments()
                    for application in applications:
                        elements.append({'data': {'id': str(n), 'label': application}, 'classes': 'end_node'})
                        #create an edge between entity and each detection
                        elements.append({'data': {'source': str(sub_node_n), 'target': str(n)}})
                        n += 1

            if category == 'Data Repos':
                if ListDrives() != None:
                    sub_node_n = n-1
                    repos = ListDrives()
                    for repo in repos:
                        elements.append({'data': {'id': str(n), 'label': repo}, 'classes': 'end_node'})
                        #create an edge between entity and each detection
                        elements.append({'data': {'source': str(sub_node_n), 'target': str(n)}})
                        n += 1
                

        #return the network graph
        return cyto.Cytoscape(
            id='entity-detection-cytoscape-nodes',
            # layout={'name': 'circle', 'radius':250},
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