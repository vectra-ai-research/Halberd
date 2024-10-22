'''
Page Navigation URL : app/recon
Page Description : Recon page hosts various reconnaissance dashboards providing fast and easy information gathering in a connected environment. 
'''

from dash import html
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify

page_layout = html.Div([
    html.H2(["Recon ", html.A(DashIconify(icon="mdi:help-circle-outline", width=18, height=18), href="https://github.com/vectra-ai-research/Halberd/wiki/UI-&-Navigation#recon-recon", target="_blank")], className="text-success mb-3"),
    dbc.Tabs(
        [
            dbc.Tab(label="Roles", tab_id="tab-recon-roles", labelClassName="text-success"),
            dbc.Tab(label="Users", tab_id="tab-recon-users", labelClassName="text-success"),
            dbc.Tab(label="Entity Map", tab_id="tab-recon-entity-map", labelClassName="text-success")
        ],
        id="recon-target-tabs",
        active_tab="tab-recon-roles",
        class_name="bg-dark"
    ),
    html.Div(id="recon-content-div",className="bg-dark", style={"height": "90vh", "justify-content": "center", "align-items": "center"}),
], className="bg-dark", style={"height": "100vh", "overflow": "auto", "padding-right": "20px", "padding-left": "20px"})