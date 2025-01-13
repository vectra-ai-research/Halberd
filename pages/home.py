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
register_page(__name__, path='/home', name='Home')

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
    # Home intro section
    dbc.Row([
        dbc.Col([
            html.H1("Welcome to Halberd", className="display-4 mb-2 halberd-brand"),
            html.P(
                "Multi-cloud attack emulation for effective security testing ",
                className="lead mb-5 halberd-brand text-secondary"
            ),
            dbc.Button("Attack", href = dash.get_relative_path("/attack"), size="lg", className="me-2 halberd-button pulse halberd-brand-heading"),
            dbc.Button("Halberd Wiki", href = "https://github.com/vectra-ai-research/Halberd/wiki", external_link=True, target='_blank', size="lg", className="halberd-button-secondary halberd-brand-heading"),
        ],
        md=8)
    ],
    className="mb-5"),
    dbc.Row([
        dbc.Col([
            # First card: Attack Surface Coverage
            dbc.Card([
                html.H4([
                    DashIconify(icon="mdi:shield-search", className="me-2"),
                    f"{len(TechniqueRegistry().list_techniques().keys())} Attack Techniques"
                ], className="d-flex align-items-center halberd-text"),
                html.P(
                    "Advanced attack emulation including privilege escalation, credential access, and lateral movement aligned with real-world TTPs.",
                    className="halberd-text"
                )
            ],
            body=True,
            className="mb-3 halberd-depth-card"),
        ],
        md=4),
        dbc.Col([
            # Second card: Cloud Coverage
            dbc.Card([
                html.H4([
                DashIconify(icon="mdi:cloud-sync", className="me-2"),
                f"{len(set(technique['surface'] for techniques in tactics_dict.values() for technique in techniques))} Cloud Platforms"
            ], className="d-flex align-items-center halberd-text"),
                html.P(
                    "Comprehensive coverage across AWS, Azure, GCP, Microsoft 365 & Entra ID. Test your entire cloud estate from a single tool.",
                    className="halberd-text"
                )
            ],
            body=True,
            className="mb-3 halberd-depth-card"),
        ],
        md=4),
        dbc.Col([
            # Third card: MITRE Alignment
            dbc.Card([
                html.H4([
                    DashIconify(icon="mdi:target-account", className="me-2"),
                    f"{len(tactics_dict)} MITRE Tactics"
                ], className="d-flex align-items-center halberd-text"),
                html.P(
                    "Full MITRE ATT&CK framework alignment with end-to-end attack chain coverage from initial access to impact.", 
                    className="halberd-text"
                )
            ],
            body=True,
            className="mb-3 halberd-depth-card"),
        ],
        md=4),
    ]),
    
    # Home main content
        dbc.Alert(
            "Halberd is for authorized security testing only. Ensure you have proper permissions before proceeding.",
            color="danger",
            dismissable=True,
            className="mb-4"
        ),
        # Matrix section header
        html.H2("Halberd Attack Matrix", className="mt-2"),
        
        # Tactics grid table
        html.Div(
            className="table-responsive",
            children=[
                html.Table(
                    className="table table-bordered",
                    children=[
                        # Header row
                        html.Thead(
                            html.Tr([
                                html.Th(
                                    [
                                        # display tactic name as header
                                        html.Div(tactic, className="font-weight-bold halberd-brand"),
                                        # list techniques count under tactic name
                                        html.Div(f"{len(tactics_dict[tactic])} techniques", className="text-muted small")
                                    ],
                                    className="bg-primary text-white text-center",
                                    style={'width': f'{100/len(tactics_order)}%'}
                                ) for tactic in tactics_order
                            ])
                        ),
                        # Technique rows
                        html.Tbody([
                            html.Tr([
                                html.Td(
                                    dbc.Button(
                                        [
                                            html.Div(
                                                tactics_dict[tactic][i]['name'] if i < len(tactics_dict[tactic]) else "",
                                                className="halberd-typography text-lg"
                                            ),
                                            html.Span(
                                                CATEGORY_MAPPING.get(tactics_dict[tactic][i]['surface'], tactics_dict[tactic][i]['surface']) if i < len(tactics_dict[tactic]) else "", 
                                                className=f"tag tag-{CATEGORY_MAPPING.get(tactics_dict[tactic][i]['surface'], tactics_dict[tactic][i]['surface']).lower()} mt-2"
                                            )
                                        ],
                                        id={'type': 'technique', 'index': tactics_dict[tactic][i]['id']} if i < len(tactics_dict[tactic]) else None,
                                        className="w-100 h-100 p-2 halberd-depth-card",
                                        style={'cursor': 'pointer'} if i < len(tactics_dict[tactic]) else {}
                                    ) if i < len(tactics_dict[tactic]) else "",
                                    className="align-top p-1",
                                    style={'height': '100px'}  # set fixed height for cells
                                ) for tactic in tactics_order
                            ]) for i in range(max_techniques)
                        ])
                    ]
                )
            ]
        ),
    
    # Home footer
    dbc.Row([
        dbc.Col([
            dcc.Link(
                html.P(f"Halberd : Multi-Cloud Attack Tool (v{__version__})", className="text-muted"), 
                href= __repository__, 
                target="_blank"
            )
        ]),
        dbc.Col([
            dcc.Link(
                f"Created by {__author__}", 
                href= "https://github.com/openrec0n", 
                target="_blank", 
                style={'float': 'right'}
            )
        ])
    ],
    className="py-3 mt-5 border-top")
], 
className="bg-halberd-dark min-vh-100", 
style={
    'minHeight': '100vh',
    "padding-right": "20px", 
    "padding-left": "20px"
    }
)

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