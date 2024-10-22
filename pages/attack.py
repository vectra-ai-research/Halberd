'''
Page Navigation url : app/attack
Page Description : Allows interaction with Halberd attack modules and execution of attack techniques.
'''

import dash_bootstrap_components as dbc
from dash import html, dcc
from dash_iconify import DashIconify
                   
page_layout = html.Div([
    html.H2(["Attack ",html.A(DashIconify(icon="mdi:help-circle-outline", width=18, height=18), href="https://github.com/vectra-ai-research/Halberd/wiki/UI-&-Navigation#attack-attack", target="_blank")], className="text-success mb-3"),
    
    dbc.Row([
        # Column 1 : Display cloud tabs
        dbc.Col([
            dbc.Tabs(
                [
                    dbc.Tab(label="EntraID", tab_id="tab-attack-EntraID", labelClassName="text-success"),
                    dbc.Tab(label="M365", tab_id="tab-attack-M365", labelClassName="text-success"),
                    dbc.Tab(label="AWS", tab_id="tab-attack-AWS", labelClassName="text-success"),
                    dbc.Tab(label="Azure", tab_id="tab-attack-Azure", labelClassName="text-success"),
                ],
                id="attack-surface-tabs",
                active_tab="tab-attack-EntraID",
                class_name="bg-dark"
            ),
        ], md=3),
    ], className="mt-3"),

    html.Br(),

    html.Div([
        dbc.Row([
            # Column 1: Display technique options radio buttons
            dbc.Col([
                html.Div([
                    html.H5("Access"),
                    html.Br(),
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
                    html.P("Tactics", style={"font-size": 20}),
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
                    dbc.Button([
                        DashIconify(icon="mdi:download"),
                    ], id="download-technique-response-button", color="primary", style={'float': 'right', 'margin-left': '10px'}),
                )
            ]
        ),
        dbc.Row(
            dcc.Loading(
                id="attack-output-loading",
                type="default",
                children=html.Div(id= "execution-output-div", style={"height":"40vh", "overflowY": "auto", "border":"1px solid #ccc", "padding-right": "10px", "padding-left": "10px", "padding-top": "10px", "padding-bottom": "10px"})
            )
        )
    ]),
    
    # Access details modal
    dbc.Modal(
        [
            dbc.ModalHeader(dbc.ModalTitle("Access Manager", className="text-success")),
            dbc.ModalBody(id = "attack-access-info-display-modal-body"),
            dbc.ModalFooter(
                dbc.Button("Close", id="close-attack-access-info-display-modal", className="ml-auto")
            ),
        ],
        id="attack-access-info-display-modal",
        size="xl",
        scrollable=True,
        backdrop="static"
    ),
], className="bg-dark", style={"height": "100vh", 'overflow': 'auto', "padding-right": "20px", "padding-left": "20px"})

    