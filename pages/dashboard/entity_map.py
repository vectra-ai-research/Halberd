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
def GenerateEntityMappingGraph():
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
            layout={'name': 'cose'},
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
                    'selector': '.detection',
                    'style': {
                        'label': 'data(label)',
                        'background-color': '#ff0000',
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
                    'selector': '.techniques',
                    'style': {
                        'label': 'data(label)',
                        'background-color': '#005000',
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
                    'selector': 'edge',
                    'style': {
                        'curve-style': 'bezier',
                        'target-arrow-shape': 'triangle',
                        'line-color': '#000000',
                        'target-arrow-color': '#000000',
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
    dbc.Button("Generate Entity Map", id="generate-entity-map-button", n_clicks=0, color="danger", style={'float': 'right', 'margin-left': '10px'}),
    dcc.Loading(
        id="attack-output-loading",
        type="default",
        children = html.Div(id = "entity-map-display-div", style= {"height": "100vh"})
    ),
    ],className = "bg-dark")