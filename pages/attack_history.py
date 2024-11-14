'''
Page Navigation url : app/attack-history
Page Description : Page to view outputs from all technique executions.
'''

import dash_bootstrap_components as dbc
from dash import html, dcc
from dash_iconify import DashIconify
from core.Functions import generate_attack_trace_table

def generate_attack_history_page():
    return html.Div([
        html.H2(["Attack History ",html.A(DashIconify(icon="mdi:help-circle-outline", width=18, height=18), href="https://github.com/vectra-ai-research/Halberd/wiki/UI-&-Navigation#attack-history", target="_blank")], className="text-success mb-3"),

        dbc.Col([
            #Column 1
            dbc.Row(
                [
                    html.Div(generate_attack_trace_table(), id= "technique-execution-trace-div", style={"height":"25vh", "overflowY": "auto", "padding-right": "10px", "padding-left": "10px", "padding-top": "10px", "padding-bottom": "10px"})
                ],
                className= "bg-dark"
            ),
            # Column 2
            dbc.Row(
                [
                    dcc.Loading(
                        id="attack-output-viewer-loading",
                        type="default",
                        children=html.Div("Select an Execution From Table to View Output", id= "output-viewer-display-div", style={"height":"60vh", "overflowY": "auto", "border":"1px solid #ccc", "padding-right": "10px", "padding-left": "10px", "padding-top": "10px", "padding-bottom": "10px"})
                    )
                ],
                className= "bg-dark"
            )
        ])
    ], 
    className="bg-dark", 
    style={
            'position': 'fixed',  # Fixed position to take up full viewport
            'top': 92,
            'left': 0,
            'right': 0,
            'bottom': 0,
            'overflow': 'auto',  # Enable scrolling
            "padding-right": "20px", 
            "padding-left": "20px",
        }
    )