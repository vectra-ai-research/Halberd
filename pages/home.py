'''
Page Navigation url : app/home
Page Description : Hosts the launch page of Halberd. Displays information regarding the tool and overview of included modules.
'''

from collections import defaultdict

import dash
from dash import dcc, html, register_page, callback
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify

from attack_techniques.technique_registry import TechniqueRegistry

from core.Functions import generate_technique_info
from core.Constants import CATEGORY_MAPPING
from version import __version__, __author__, __repository__

# Register page to app
register_page(__name__, path='/', name='Home')

# Initialize tactics_dict 
tactics_dict = defaultdict(list)

# Process all techniques data
for technique_class, technique in TechniqueRegistry.list_techniques().items():
    t = technique()
    tactics = []
    for mitre_technique in t.mitre_techniques:
        tactics += mitre_technique.tactics

    tactics = list(set(tactics))
    # Add technique to each associated tactic in tactics_dict
    for tactic in tactics:
        tactics_dict[tactic].append({
            'id': technique_class,
            'name': t.name,
            'surface': TechniqueRegistry.get_technique_category(technique_class)
        })

# Tactics order to follow typical kill chain 
tactics_order = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Exfiltration',
    'Impact'
]

# Find maximum number of techniques in any tactic
max_techniques = max(len(techniques) for techniques in tactics_dict.values())

# Home layout
layout = html.Div([
    # Hero section
    html.Div([
        html.Div([
            # Main brand and action section
            html.Div([
                html.H1([
                    html.Img(
                        src="/assets/favicon.ico",
                        className="halberd-logo me-3",
                        style={
                            "width": "60px",
                            "height": "60px",
                            "filter": "drop-shadow(0 4px 8px rgba(220, 53, 69, 0.3))"
                        }
                    ),
                    "HALBERD"
                ], className="hero-title mb-4"),
                html.P(
                    "Advanced Multi-Cloud Attack Emulation Tool",
                    className="hero-subtitle mb-5"
                ),
                html.Div([
                    dbc.Button([
                        html.I(className="fas fa-crosshairs me-2"),
                        "Launch Attack"
                    ], 
                    href=dash.get_relative_path("/attack"), 
                    size="lg", 
                    className="hero-cta-primary me-3",
                    style={
                        "background": "linear-gradient(135deg, #dc3545 0%, #c82333 100%)",
                        "border": "none",
                        "padding": "12px 30px",
                        "fontSize": "1.1rem",
                        "fontWeight": "600",
                        "borderRadius": "8px",
                        "boxShadow": "0 4px 20px rgba(220, 53, 69, 0.4)",
                        "transition": "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)"
                    }),
                    dbc.Button([
                        html.I(className="fab fa-github me-2"),
                        "Documentation"
                    ], 
                    href="https://github.com/vectra-ai-research/Halberd/wiki", 
                    external_link=True, 
                    target='_blank', 
                    size="lg", 
                    outline=True,
                    color="light",
                    className="hero-cta-secondary",
                    style={
                        "border": "2px solid rgba(255, 255, 255, 0.2)",
                        "padding": "12px 30px",
                        "fontSize": "1.1rem",
                        "fontWeight": "600",
                        "borderRadius": "8px",
                        "backdropFilter": "blur(10px)",
                        "transition": "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)"
                    })
                ], className="hero-actions mb-5")
            ], className="hero-content text-center")
        ], className="container")
    ], className="hero-section", style={
        "background": "linear-gradient(135deg, rgba(33, 37, 41, 0.95) 0%, rgba(52, 58, 64, 0.95) 50%, rgba(33, 37, 41, 0.95) 100%)",
        "paddingTop": "80px",
        "paddingBottom": "80px",
        "marginBottom": "60px",
        "position": "relative",
        "overflow": "hidden"
    }),

    # Stats cards section
    html.Div([
        dbc.Row([
            dbc.Col([
                html.Div([
                    html.Div([
                        html.Div([
                            DashIconify(
                                icon="mdi:shield-search", 
                                className="stats-icon",
                                style={"fontSize": "2.5rem", "color": "#dc3545"}
                            )
                        ], className="stats-icon-container"),
                        html.Div([
                            html.H3(
                                f"{len(TechniqueRegistry().list_techniques().keys())}", 
                                className="stats-number"
                            ),
                            html.P("Attack Techniques", className="stats-label")
                        ], className="stats-text")
                    ], className="stats-content"),
                    html.P(
                        "Advanced attack emulation with real-world TTPs",
                        className="stats-description"
                    )
                ], className="enhanced-stats-card")
            ], md=3, className="mb-4"),
            
            dbc.Col([
                html.Div([
                    html.Div([
                        html.Div([
                            DashIconify(
                                icon="mdi:cloud-sync", 
                                className="stats-icon",
                                style={"fontSize": "2.5rem", "color": "#17a2b8"}
                            )
                        ], className="stats-icon-container"),
                        html.Div([
                            html.H3(
                                f"{len(set(technique['surface'] for techniques in tactics_dict.values() for technique in techniques))}", 
                                className="stats-number"
                            ),
                            html.P("Cloud Platforms", className="stats-label")
                        ], className="stats-text")
                    ], className="stats-content"),
                    html.P(
                        "Comprehensive coverage across major cloud providers",
                        className="stats-description"
                    )
                ], className="enhanced-stats-card")
            ], md=3, className="mb-4"),
            
            dbc.Col([
                html.Div([
                    html.Div([
                        html.Div([
                            DashIconify(
                                icon="mdi:target-account", 
                                className="stats-icon",
                                style={"fontSize": "2.5rem", "color": "#28a745"}
                            )
                        ], className="stats-icon-container"),
                        html.Div([
                            html.H3(
                                f"{len(tactics_dict)}", 
                                className="stats-number"
                            ),
                            html.P("MITRE Tactics", className="stats-label")
                        ], className="stats-text")
                    ], className="stats-content"),
                    html.P(
                        "Full ATT&CK framework alignment and coverage",
                        className="stats-description"
                    )
                ], className="enhanced-stats-card")
            ], md=3, className="mb-4"),
            
            dbc.Col([
                html.Div([
                    html.Div([
                        html.Div([
                            DashIconify(
                                icon="mdi:robot", 
                                className="stats-icon",
                                style={"fontSize": "2.5rem", "color": "#6f42c1"}
                            )
                        ], className="stats-icon-container"),
                        html.Div([
                            html.H3("AI", className="stats-number"),
                            html.P("Attack Agent", className="stats-label")
                        ], className="stats-text")
                    ], className="stats-content"),
                    html.P(
                        "LLM-powered intelligent attack workflows",
                        className="stats-description"
                    )
                ], className="enhanced-stats-card")
            ], md=3, className="mb-4"),
        ], className="g-4")
    ], className="container mb-5"),

    # Security notice with modern styling
    html.Div([
        dbc.Alert([
            html.Div([
                html.I(className="fas fa-exclamation-triangle me-3", style={"fontSize": "1.2rem"}),
                html.Span("For authorized security testing only. Ensure proper permissions before proceeding.", 
                         style={"fontSize": "1rem", "fontWeight": "500"})
            ], className="d-flex align-items-center")
        ],
        color="danger",
        dismissable=True,
        className="security-notice",
        style={
            "background": "linear-gradient(135deg, rgba(220, 53, 69, 0.1) 0%, rgba(220, 53, 69, 0.05) 100%)",
            "border": "1px solid rgba(220, 53, 69, 0.3)",
            "borderRadius": "12px",
            "backdropFilter": "blur(10px)"
        })
    ], className="container mb-5"),
        
    # Matrix section
    html.Div([
        html.Div([
            html.H2([
                html.I(className="fas fa-th me-3", style={"color": "#dc3545"}),
                "Attack Technique Matrix"
            ], className="matrix-title mb-4"),
            
            # Matrix container
            html.Div([
                html.Div(
                    className="table-responsive enhanced-matrix-responsive",
                    children=[
                        html.Table(
                            className="table enhanced-matrix-table",
                            children=[
                                # Header row
                                html.Thead(
                                    html.Tr([
                                        html.Th([
                                            html.Div([
                                                html.H5(tactic, className="tactic-name mb-1"),
                                                html.Span(f"{len(tactics_dict[tactic])} techniques", className="tactic-count")
                                            ], className="tactic-header-content")
                                        ],
                                        className="enhanced-matrix-header",
                                        style={'width': f'{100/len(tactics_order)}%'}
                                        ) for tactic in tactics_order
                                    ], className="matrix-header-row")
                                ),
                                # Technique rows
                                html.Tbody([
                                    html.Tr([
                                        html.Td([
                                            dbc.Button([
                                                html.Div([
                                                    html.H6(
                                                        tactics_dict[tactic][i]['name'] if i < len(tactics_dict[tactic]) else "",
                                                        className="technique-name mb-2"
                                                    ),
                                                    html.Span(
                                                        CATEGORY_MAPPING.get(tactics_dict[tactic][i]['surface'], tactics_dict[tactic][i]['surface']) if i < len(tactics_dict[tactic]) else "", 
                                                        className=f"platform-tag platform-{CATEGORY_MAPPING.get(tactics_dict[tactic][i]['surface'], tactics_dict[tactic][i]['surface']).lower()}" if i < len(tactics_dict[tactic]) else ""
                                                    )
                                                ], className="technique-card-content")
                                            ],
                                            id={'type': 'technique', 'index': tactics_dict[tactic][i]['id']} if i < len(tactics_dict[tactic]) else None,
                                            className="enhanced-technique-card w-100 h-100",
                                            style={
                                                "minHeight": "120px",
                                                "background": "linear-gradient(135deg, rgba(52, 58, 64, 0.8) 0%, rgba(33, 37, 41, 0.8) 100%)" if i < len(tactics_dict[tactic]) else "transparent",
                                                "border": "1px solid rgba(255, 255, 255, 0.1)" if i < len(tactics_dict[tactic]) else "none",
                                                "borderRadius": "8px",
                                                "backdropFilter": "blur(10px)",
                                                "transition": "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
                                                "cursor": "pointer" if i < len(tactics_dict[tactic]) else "default"
                                            }
                                            ) if i < len(tactics_dict[tactic]) else html.Div(style={"minHeight": "120px"}),
                                        ],
                                        className="enhanced-matrix-cell align-top p-2"
                                        ) for tactic in tactics_order
                                    ], className="matrix-technique-row") for i in range(max_techniques)
                                ])
                            ]
                        )
                    ]
                )
            ], className="matrix-wrapper")
        ], className="container")
    ], className="matrix-section mb-5"),
    
    # Footer
    html.Div([
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.P([
                            html.Img(
                                src="/assets/favicon.ico",
                                className="footer-logo me-2",
                                style={
                                    "width": "20px",
                                    "height": "20px",
                                    "filter": "drop-shadow(0 2px 4px rgba(220, 53, 69, 0.3))"
                                }
                            ),
                            f"Halberd v{__version__}"
                        ], className="footer-brand mb-2"),
                        dcc.Link(
                            "Multi-Cloud Attack Emulation Tool", 
                            href=__repository__, 
                            target="_blank",
                            className="footer-link"
                        )
                    ])
                ], md=6),
                dbc.Col([
                    html.Div([
                        html.P("Created by", className="footer-credit mb-1"),
                        dcc.Link(
                            __author__, 
                            href="https://github.com/openrec0n", 
                            target="_blank",
                            className="footer-author-link"
                        )
                    ], className="text-md-end")
                ], md=6)
            ])
        ], className="container")
    ], className="footer-section", style={
        "background": "linear-gradient(135deg, rgba(33, 37, 41, 0.95) 0%, rgba(52, 58, 64, 0.95) 100%)",
        "borderTop": "1px solid rgba(255, 255, 255, 0.1)",
        "paddingTop": "40px",
        "paddingBottom": "40px",
        "marginTop": "80px"
    })
], 
className="bg-halberd-dark min-vh-100 enhanced-home-page", 
style={
    'minHeight': '100vh',
    "position": "relative"
})

'''Callback to open modal and display technique information from home techniques matrix'''
@callback(
    Output("app-technique-info-display-modal", "is_open", allow_duplicate=True),
    Output("app-technique-info-display-modal-body", "children", allow_duplicate = True),
    Input({"type": "technique", "index": dash.ALL}, "n_clicks"),
    State("app-technique-info-display-modal", "is_open"),
    prevent_initial_call=True
)
def toggle_app_modal_from_home_matrix_callback(n_clicks, is_open):
    # Prevent call back on page load
    if any(item is not None for item in n_clicks):
        if not dash.callback_context.triggered:
            return is_open, ""
        
        # Extract technique id
        triggered_id = dash.callback_context.triggered[0]["prop_id"]
        technique_id = eval(triggered_id.split(".")[0])["index"]

        # Generate technique information
        technique_details = generate_technique_info(technique_id)
        
        return not is_open, technique_details
    else:
        raise PreventUpdate