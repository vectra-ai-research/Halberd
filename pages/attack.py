'''
Name : attack.py
Description : Defines the page layout for /attack page
'''
import dash_bootstrap_components as dbc
from dash import html

page_layout = html.Div([
    dbc.Tabs(
        [
            dbc.Tab(label="EntraID", tab_id="tab-attack-EntraID", labelClassName="text-success"),
            dbc.Tab(label="M365", tab_id="tab-attack-M365", labelClassName="text-success"),
            dbc.Tab(label="AWS", tab_id="tab-attack-AWS", labelClassName="text-success"),
            # dbc.Tab(label="Azure", tab_id="tab-attack-Azure", labelClassName="text-success"),
        ],
        id="attack-surface-tabs",
        active_tab="tab-attack-EntraID",
        class_name="bg-dark"
    ),
    html.Div(id="tabs-content-div",className="bg-dark", style={"height": "90vh", "justify-content": "center", "align-items": "center"}),
], className="bg-dark", style={"height": "100vh", 'overflow': 'auto'})