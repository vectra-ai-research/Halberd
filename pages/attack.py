'''
Page Navigation url : app/attack
Page Description : Allows interaction with Halberd attack modules and execution of attack techniques.
'''

import dash_bootstrap_components as dbc
from dash import html, dcc
from dash_iconify import DashIconify
                   
page_layout = html.Div([
    html.H2(["Attack ",html.A(DashIconify(icon="mdi:help-circle-outline", width=18, height=18), href="https://github.com/vectra-ai-research/Halberd/wiki/UI-&-Navigation#attack-attack", target="_blank")], className="text-success mb-3"),

    html.Div([
        dbc.Row([
            # Column 1: Display technique options radio buttons
            dbc.Col([
                html.H5("Technique Options"),
                html.Br(),
                html.Div([
                    dbc.Label("Attack Surface"),
                    dbc.Tabs(
                        [
                            dbc.Tab(label="EntraID", tab_id="tab-attack-EntraID", labelClassName="text-success",
                                tab_style={
                                    'borderRadius': '0px',
                                    'margin': '0px',
                                    'marginLeft': '0px',
                                    'marginRight': '0px'
                                }
                            ),
                            dbc.Tab(
                                label="M365", tab_id="tab-attack-M365", labelClassName="text-success",
                                tab_style={
                                    'borderRadius': '0px',
                                    'margin': '0px',
                                    'marginLeft': '0px',
                                    'marginRight': '0px'
                                }
                            ),
                            dbc.Tab(
                                label="AWS", tab_id="tab-attack-AWS", labelClassName="text-success",
                                tab_style={
                                    'borderRadius': '0px',
                                    'margin': '0px',
                                    'marginLeft': '0px',
                                    'marginRight': '0px'
                                }
                            ),
                                dbc.Tab(label="Azure", tab_id="tab-attack-Azure", labelClassName="text-success",
                                tab_style={
                                    'borderRadius': '0px',
                                    'margin': '0px',
                                    'marginLeft': '0px',
                                    'marginRight': '0px'
                                }
                            ),
                                dbc.Tab(label="GCP", tab_id="tab-attack-GCP", labelClassName="text-success",
                                tab_style={
                                    'borderRadius': '0px',
                                    'margin': '0px',
                                    'marginLeft': '0px',
                                    'marginRight': '0px'
                                }
                            ),
                        ],
                        id="attack-surface-tabs",
                        active_tab="tab-attack-EntraID",
                        # class_name="bg-dark"
                    ),
                    html.Br(),
                    dbc.Label("Access"),
                    dbc.Button(
                        "Establish Access", 
                        id="attack-access-info-dynamic-btn", 
                        color="success", 
                        className="mb-3 bg-dark",
                        outline=True,
                        style = {
                            'width': '20vw',
                            'display': 'flex',
                            'justify-content': 'center',
                            'align-items': 'center'
                        }
                    ),
                    dbc.Label("Tactics"),
                    dcc.Dropdown(id = "tactic-dropdown", className= "bg-dark"),
                    html.Br(),
                    html.P("Techniques", style={"font-size": 20}),
                    html.Div(id="attack-techniques-options-div", className= "bg-dark")
                ], className= "bg-dark mx-3"),
            ],  md=3, className="bg-dark border-end"),
            
            # Column 2 : Display technique configuration
            dbc.Col([
                html.H5("Attack Technique Config"),
                html.Br(),
                html.Div(id="attack-config-div", className="mx-3")
            ], md=6, className="bg-dark border-end"),
            
            # Column 3 : Display technique information
            dbc.Col([
                html.H5("Technique Information"),
                html.Br(),
                html.Div(id="attack-technique-info-div")
            ],  md=3, className="bg-dark")
        ]),
    ], style={"justify-content": "center", "align-items": "center"}),
    
    html.Br(),
    # Display technique output
    dcc.Store(id="technique-output-memory-store"),
    dbc.Col([
        dbc.Row(
            [
                dbc.Col(
                    html.H4("Response")
                ),
                dbc.Col(
                    html.A(
                        dbc.Button(
                            [
                                DashIconify(
                                    icon="mdi:history",
                                    width=20,
                                    className="me-1"
                                ),
                                "View Attack History"
                            ],
                            n_clicks=0,
                            color="primary",
                            className="ms-2",
                            id="history-button",
                        ),
                        href="/attack-history", 
                        target="_blank", 
                        style={'float': 'right', 'margin-left': '10px'}
                    )
                )
            ]
        ),
        dbc.Row(
            [
                dbc.Col(
                    dcc.Loading(
                        id="attack-output-loading",
                        type="default",
                        children=html.Div(id= "execution-output-div", style={"height":"40vh", "overflowY": "auto", "border":"1px solid #ccc", "padding-right": "10px", "padding-left": "10px", "padding-top": "10px", "padding-bottom": "10px"})
                    )
                )
            ]
        )
    ]),
    
    # Access details modal
    dbc.Modal(
        [
            dbc.ModalHeader(dbc.ModalTitle("Access Manager", className="text-success")),
            dbc.ModalBody(id = "attack-access-info-display-modal-body")
        ],
        id="attack-access-info-display-modal",
        size="xl",
        scrollable=True,
        backdrop="static"
    ),
],
className="bg-dark",
style={
    'minHeight': '100vh',
    "padding-right": "20px", 
    "padding-left": "20px"
    }
)