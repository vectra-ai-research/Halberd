'''
Page Navigation URL : app/recon
Page Description : Recon page hosts various reconnaissance dashboards providing fast and easy information gathering in a connected environment. 
'''

from dash import html, callback, register_page
from dash.dependencies import Input, Output
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

from pages.dashboard.entity_map import generate_entity_mapping_graph

# Register page to app
register_page(__name__, path='/recon', name='Recon')

layout = html.Div(
    [
        # Recon dashboard tabs
        dbc.Tabs(
            [
                dbc.Tab(
                    label="Roles", 
                    tab_id="tab-recon-roles", 
                    labelClassName="halberd-brand-heading text-danger"
                ),
                dbc.Tab(
                    label="Users", 
                    tab_id="tab-recon-users", 
                    labelClassName="halberd-brand-heading text-danger"
                ),
                dbc.Tab(
                    label="Entity Map", 
                    tab_id="tab-recon-entity-map", 
                    labelClassName="halberd-brand-heading text-danger"
                )
            ],
            id="recon-target-tabs",
            active_tab="tab-recon-roles",
            class_name="bg-halberd-dark"
        ),
        # Div to display recon dashboards
        html.Div(
            id="recon-content-div",
            className="bg-halberd-dark", 
            style={
                "height": "90vh", 
                "justify-content": "center", 
                "align-items": "center"
            }
        ),
    ], 
    className="bg-halberd-dark", 
    style={
        "height": "100vh", 
        "overflow": "auto", 
        "padding-right": "20px", 
        "padding-left": "20px"
    }
)

'''Recon page tab switcher'''
@callback(
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
    
'''Entity Map - Generate Map'''
@callback(
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

    return generate_entity_mapping_graph(map_layout, filter_category)

'''Callback to display entity map node information'''
@callback(
    Output("entity-map-node-info-div", "children"),
    Input("entity-detection-cytoscape-nodes", "tapNodeData"),
)
def display_entity_map_node_info_callback(data):
    if not data:
        return "Click on a node to see more information."
    return f"Selected Node: {data['label']}"

'''Callback to generate data in role recon dashboard'''
@callback(
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

    print(1)

    return role_name, role_template_id, role_id, member_count, role_members, role_description

'''Callback to generate data in user recon dashboard'''
@callback(Output(
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