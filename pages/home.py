'''
Page Navigation url : app/home
Page Description : Hosts the launch page of Halberd. Displays information regarding the tool and overview of included modules.
'''

import dash
import dash_bootstrap_components as dbc
from dash import html,dcc
from collections import defaultdict
from attack_techniques.technique_registry import TechniqueRegistry

# Initialize tactics_dict 
tactics_dict = defaultdict(list)

# Process all techniques data
for technique_class, technique in TechniqueRegistry.list_techniques().items():
    t = technique()
    tactics = []
    for mitre_technique in t.mitre_techniques:
        tactics += mitre_technique.tactics

    tactics = list(set(tactics))
    # add technique to each associated tactic in tactics_dict
    for tactic in tactics:
        tactics_dict[tactic].append({
            'id': technique_class,
            'name': t.name,
            'surface': TechniqueRegistry.get_technique_category(technique_class)
        })

# tactics order to follow typical kill chain 
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

# find maximum number of techniques in any tactic
max_techniques = max(len(techniques) for techniques in tactics_dict.values())

# home layout
page_layout = html.Div([
    # home intro section
    dbc.Row([
        dbc.Col([
            html.H1("Welcome to Halberd", className="display-4 mb-4 text-success"),
            html.P(
                "Execute security testing with advanced attack emulation across cloud environments.",
                className="lead mb-4"
            ),
            dbc.Button("Attack", href = dash.get_relative_path("/attack"), color="light", size="lg", className="me-2"),
            dbc.Button("Learn More", href = "https://github.com/vectra-ai-research/Halberd/wiki", external_link=True, target='_blank', color="primary", size="lg"),
        ],
        md=8)
    ],
    className="py-5"),
    dbc.Row([
        dbc.Col([
            dbc.Card([
                html.H4(f"{len(TechniqueRegistry().list_techniques().keys())} Techniques", className="card-title"),
                html.P("Covering a wide range of attack vectors", className="card-text")
            ],
            body=True,
            className="mb-3"),
        ],
        md=4),
        dbc.Col([
            dbc.Card([
                html.H4(f"{len(set(technique['surface'] for techniques in tactics_dict.values() for technique in techniques))} Attack Surfaces", className="card-title"),
                html.P("Coverage across major cloud platforms", className="card-text")
            ],
            body=True,
            className="mb-3"),
        ],
        md=4),
        dbc.Col([
            dbc.Card([
                html.H4(f"{len(tactics_dict)} Tactics", className="card-title"),
                html.P("Aligned with the MITRE ATT&CK framework", className="card-text")
            ],
            body=True,
            className="mb-3"),
        ],
        md=4),
    ]),
    
    # home main content
        dbc.Alert(
            "This tool is for authorized security testing only. Ensure you have proper permissions before proceeding.",
            color="danger",
            dismissable=True,
            className="mb-4"
        ),
        
        # matrix section header
        html.H2("Halbed Attack Techniques Matrix", className="mb-4"),
        
        # tactics grid table
        html.Div(
            className="table-responsive",
            children=[
                html.Table(
                    className="table table-bordered",
                    children=[
                        # header row
                        html.Thead(
                            html.Tr([
                                html.Th(
                                    [
                                        # display tactic name as header
                                        html.Div(tactic, className="font-weight-bold"),
                                        # list techniques count under tactic name
                                        html.Div(f"{len(tactics_dict[tactic])} techniques", className="text-muted small")
                                    ],
                                    className="bg-primary text-white text-center",
                                    style={'width': f'{100/len(tactics_order)}%'}
                                ) for tactic in tactics_order
                            ])
                        ),
                        # technique rows
                        html.Tbody([
                            html.Tr([
                                html.Td(
                                    dbc.Button(
                                        [
                                            html.Div(
                                                tactics_dict[tactic][i]['name'] if i < len(tactics_dict[tactic]) else "",
                                                className="font-weight-bold"
                                            ),
                                            html.Div(
                                                f"[{tactics_dict[tactic][i]['surface']}]" if i < len(tactics_dict[tactic]) else "",
                                                className="text-muted small"
                                            )
                                        ],
                                        id={'type': 'technique', 'index': tactics_dict[tactic][i]['id']} if i < len(tactics_dict[tactic]) else None,
                                        color="light",
                                        className="w-100 h-100 p-2",
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
    
    # home footer
    dbc.Row([
        dbc.Col([
            html.P(f"Halberd Security Testing (v2.0).", className="text-muted")
        ]),
        dbc.Col([
            dcc.Link("Created by @openrec0n (Arpan Sarkar)", href= "https://github.com/openrec0n", target="_blank", style={'float': 'right'})
        ])
    ],
    className="py-3 mt-5 border-top")
], className="bg-dark min-vh-100", style={ "height": "100vh", "padding-right": "20px", "padding-left": "20px"})