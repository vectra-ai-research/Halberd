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
        html.H2(
            [
                "Attack History ",
                html.A(DashIconify(icon="mdi:help-circle-outline", width=18, height=18), href="https://github.com/vectra-ai-research/Halberd/wiki/UI-&-Navigation#attack-history", target="_blank")
            ],
            className="halberd-brand mb-3"
        ),

        dbc.Col([
            # Row 1 : Display execution history table
            dbc.Row(
                [
                    html.Div(
                        generate_attack_trace_table(), 
                        id= "technique-execution-trace-div", 
                        style={
                            "height":"35vh", 
                            "overflowY": "auto", 
                            "padding-right": "10px", 
                            "padding-left": "10px", 
                            "padding-top": "10px", 
                            "padding-bottom": "5px"
                        }
                    )
                ],
                className= "bg-halberd-dark",
            ),
            # Row 2: Display selected execution output
            dbc.Row(
                [
                    dcc.Loading(
                        id="attack-output-viewer-loading",
                        type="default",
                        children=html.Div(
                            # Default message when no execution is selected
                            html.Div([
                                dbc.Col([
                                    dbc.Row(
                                        DashIconify(
                                            icon="mdi:information-outline", #Information icon
                                            width=48,
                                            height=48,
                                            className="text-muted mb-3 me-3"
                                        )
                                    ),
                                    dbc.Row(
                                        html.P("Select Execution From Table to View Output")
                                    )
                                ])
                                ], 
                                className="halberd-text text-muted",
                                style={
                                    'textAlign': 'center',
                                    'height': '50vh',
                                    'display': 'flex',
                                    'alignItems': 'center',
                                    'justifyContent': 'center',
                                }
                            ), 
                            id= "output-viewer-display-div", 
                            style={
                                "height":"54vh", 
                                "overflowY": "auto", 
                                "border":"1px solid #ccc", 
                                "padding-right": "10px", 
                                "padding-left": "10px", 
                                "padding-top": "10px",
                                "padding-bottom": "10px"
                            },
                            className="halberd-text"
                        )
                    )
                ],
                className= "bg-halberd-dark"
            )
        ])
    ], 
    className="bg-halberd-dark", 
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