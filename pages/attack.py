'''
Page Navigation url : app/attack
Page Description : Configure and execute Halberd attack techniques and view technique response.
'''

import dash_bootstrap_components as dbc
from dash import html, dcc
from dash_iconify import DashIconify
                   
page_layout = html.Div([
    html.Div([
        dbc.Row([
            # Column 1: Display technique selection options
            dbc.Col([
                html.Div([
                    dbc.Tabs(
                        [
                            dbc.Tab(label="Entra ID", tab_id="tab-attack-EntraID", labelClassName="halberd-brand-heading text-danger",
                                tab_style={
                                    'borderRadius': '0px',
                                    'margin': '0px',
                                    'marginLeft': '0px',
                                    'marginRight': '0px'
                                }
                            ),
                            dbc.Tab(
                                label="M365", tab_id="tab-attack-M365", labelClassName="halberd-brand-heading text-danger",
                                tab_style={
                                    'borderRadius': '0px',
                                    'margin': '0px',
                                    'marginLeft': '0px',
                                    'marginRight': '0px'
                                }
                            ),
                            dbc.Tab(
                                label="AWS", tab_id="tab-attack-AWS", labelClassName="halberd-brand-heading text-danger",
                                tab_style={
                                    'borderRadius': '0px',
                                    'margin': '0px',
                                    'marginLeft': '0px',
                                    'marginRight': '0px'
                                }
                            ),
                                dbc.Tab(label="Azure", tab_id="tab-attack-Azure", labelClassName="halberd-brand-heading text-danger",
                                tab_style={
                                    'borderRadius': '0px',
                                    'margin': '0px',
                                    'marginLeft': '0px',
                                    'marginRight': '0px'
                                }
                            ),
                        ],
                        id="attack-surface-tabs",
                        active_tab="tab-attack-EntraID"
                    ),
                    # Technique section heading
                    html.P(
                        "Technique", 
                        className="halberd-brand-heading mt-4 mb-2"
                    ),
                    # Tactics dropdown
                    dcc.Dropdown(
                        id = "tactic-dropdown", 
                        className= "halberd-dropdown mb-2"
                    ),
                    # Div to display techniques list
                    html.Div(
                        id="attack-techniques-options-div"
                    )
                ], className= "bg-halberd-dark mx-3"),
            ],  md=3, className="bg-halberd-dark"),
            
            # Column 2 : Display technique information
            dbc.Col([
                html.Div(id="attack-technique-info-div")
            ],  md=4, className="bg-halberd-dark"),
            
            # Column 3 : Display technique configuration
            dbc.Col([
                html.H5("Technique Configuration", className="halberd-brand-heading text-2xl mb-4"),
                html.Div(id="attack-config-div", className="p-4 halberd-depth-card")
            ], md=5, className="bg-halberd-dark"),    
        ]),
    ], style={"justify-content": "center", "align-items": "center"},
    className="mb-3"
    ),
    
    # Display technique output
    dcc.Store(id="technique-output-memory-store"),
    dbc.Col([
        dbc.Row(
            [
                dbc.Col(
                    html.H4("Response", className="halberd-brand")
                ),
                dbc.Col(
                    html.A(
                        dbc.Button(
                            [
                                DashIconify(
                                    icon="mdi:history",
                                    width=20,
                                    className="me-2"
                                ),
                                "Attack History"
                            ],
                            n_clicks=0,
                            className="ms-2 halberd-button-secondary",
                            id="history-button",
                        ),
                        href="/attack-history", 
                        target="_blank", 
                        style={'float': 'right', 'margin-left': '10px'},
                        className= "halberd-text"
                    )
                )
            ],
            className= "mb-2"
        ),
        dbc.Row(
            [
                dbc.Col(
                    dcc.Loading(
                        id="attack-output-loading",
                        type="default",
                        children=html.Div(
                            [
                                dbc.Col([
                                    dbc.Row(
                                        DashIconify(
                                            icon="mdi:information-outline", #Information icon
                                            width=48,
                                            height=48,
                                            className="text-muted mb-3 me-3"
                                        ),
                                    ),
                                    dbc.Row(
                                        html.P("Execute Technique to View Response") # Default message when no technique is executed
                                    )
                                ], 
                                className="halberd-text text-muted",
                                style={
                                    'textAlign': 'center',
                                    'height': '35vh',
                                    'display': 'flex',
                                    'alignItems': 'center',
                                    'justifyContent': 'center',
                                })
                            ],
                            id= "execution-output-div", 
                            style={
                                "height":"40vh", 
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
                )
            ]
        )
    ]),
    
    # Access details modal
    dbc.Modal(
        [
            dbc.ModalHeader(dbc.ModalTitle("Access Manager", className="halberd-brand")),
            dbc.ModalBody(id = "attack-access-info-display-modal-body")
        ],
        id="attack-access-info-display-modal",
        size="xl",
        scrollable=True,
        backdrop="static"
    ),
],
className="bg-halberd-dark halberd-text",
style={
    'minHeight': '100vh',
    "padding-right": "20px", 
    "padding-left": "20px"
    }
)