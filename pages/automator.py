'''
Page Navigation URL : app/automator
Page Description : Manage (add/edit/schedule/import/export) and execute playbooks.
'''

import os
import json
import threading
from datetime import date

import dash
from dash import dcc, html, ALL, callback_context, no_update, MATCH, register_page, callback
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify
import dash_daq as daq

from attack_techniques.technique_registry import TechniqueRegistry

from core.playbook.playbook import Playbook
from core.playbook.playbook_step import PlaybookStep
from core.playbook.playbook_error import PlaybookError
from core.Functions import generate_technique_info, AddNewSchedule, GetAllPlaybooks, playbook_viz_generator, get_playbook_stats, parse_execution_report, generate_attack_technique_config, generate_remove_btn
from core.Constants import AUTOMATOR_PLAYBOOKS_DIR, AUTOMATOR_OUTPUT_DIR

# Register page to app
register_page(__name__, path='/automator', name='Automator')

def create_playbook_manager_layout():
    """Creates the playbook management interface layout"""
    return html.Div([
        dbc.Row([
            # Left Panel - Playbook List
            dbc.Col([
                # Primary management buttons       
                dbc.Row([
                    dbc.Col(
                        # New playbook button
                        dbc.Button(
                            [
                                DashIconify(
                                    icon="mdi:plus",
                                    width=24,
                                    height=24,
                                    className="me-2"
                                ),
                                "New Playbook"
                            ], 
                            id="open-creator-win-playbook-button", 
                            n_clicks=0,
                            className="me-2 halberd-button-secondary",
                            style={'width':'100%'}
                        ),
                        md=4
                    ),
                    dbc.Col(
                        # Import playbook button
                        dcc.Upload(
                            id="upload-playbook",
                            children=dbc.Button(
                                [
                                    DashIconify(
                                        icon="material-symbols:upload-file",  # Upload file icon for import
                                        width=24,
                                        height=24,
                                        className="me-2"
                                    ),
                                    "Import"
                                ],
                                id="import-pb-button", 
                                n_clicks=0,  
                                className="me-2 halberd-button-secondary",
                                style={'width':'100%'}
                            ),
                        ),
                        md=4
                    ),
                    dbc.Col(
                        html.Div(
                            # View progress button
                            dbc.Button(
                                    [
                                    DashIconify(
                                        icon="mdi:progress-clock",
                                        width=20,
                                        className="me-2"
                                    ),
                                    "View Progress"
                                ],
                                id="view-progress-button",
                                n_clicks=0,
                                className="me-2 halberd-button-secondary",
                                style={'width':'100%'}
                            ),
                            id="view-progress-button-container"
                        ),
                        md=4
                    )
                ],className="mb-3"),
                # Search bar
                html.Div([
                    dbc.InputGroup([
                        dbc.InputGroupText(
                            DashIconify(
                                icon="mdi:magnify", 
                                width=24,
                                height=24,
                                className="text-muted"
                            ),
                            className="bg-halberd-dark"
                        ),
                        dbc.Input(
                            id="playbook-search",
                            placeholder="Search Playbook...",
                            type="text",
                            className="bg-halberd-dark halberd-text halberd-input",
                        ),
                    ], className="w-100")
                ], className="pb-3"),
                # Playbook list
                html.Div(
                    id="playbook-list-container",
                    style={
                        'overflowY': 'auto',
                        'height':'76vh'
                    }
                )
            ], width=4, className="bg-halberd-dark"),

            # Right Panel - Playbook Visualization
            dbc.Col([
                html.Div(
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
                                html.P("Select a playbook to view details") # Default message when no playbook is selected
                            )
                        ], 
                        className="halberd-text text-muted",
                        style={
                            'textAlign': 'center',
                            'height': '50vh',
                            'display': 'flex',
                            'alignItems': 'center',
                            'justifyContent': 'center',
                        })
                    ],
                    id="playbook-visualization-container",
                    className="d-flex justify-content-center align-items-center ms-4 p-1",
                )
            ], width=8, className="p-0")
        ], className="g-0 flex-fill"),

        # Status Bar
        html.Div([
            # Left side - Ready status
            html.Div([
                html.Div(
                    "Ready",
                    className="bg-success rounded-circle me-2", 
                    style={"width": "8px", "height": "8px"}),
            ], className="d-flex align-items-center text-muted"),
            
            # Right side - Stats
            html.Div(
                id="playbook-stats",
                className="text-muted"
            )
        ], className="d-flex justify-content-between p-2 border-top border-secondary"),

        # Add stores and intervals for progress tracking
        dcc.Interval(
            id="execution-interval",
            interval=1000,  # 1 second refresh
            disabled=True
        ),
        
        # Element to trigger download/export of playbooks
        dcc.Download(id="download-pb-config-file"),
        # Memory store to save selected playbook context
        dcc.Store(id='selected-playbook-data', data={}),
        dcc.Store(id='selected-playbook-data-editor-memory-store', data={}),
        
        # Primary off canvas to support various workflows
        dbc.Offcanvas(
            id="automator-offcanvas",
            is_open=False,
            placement="end",
            style={
                "width": "50%",  # Set width to 50% of screen
                "max-width": "none"  # Override default max-width
            },
            className="bg-halberd-dark halberd-offcanvas halberd-text"
        ),
        # Off canvas for playbook editing workflow
        generate_playbook_editor_offcanvas(),
        # Add progress off-canvas
        create_execution_progress_offcanvas(),
    ], 
    className="bg-halberd-dark d-flex flex-column",
    style={
        'minHeight': '91vh',
        "padding-right": "20px", 
        "padding-left": "20px"
        }
    )

def create_playbook_item(playbook_config):
    """
    Creates a playbook item with click selection functionality and action buttons.
    Makes the entire card clickable while maintaining separate button actions.
    
    Args:
        playbook_config: Playbook configuration object containing playbook metadata
        
    Returns:
        dash.html.Div: A clickable playbook card component with actions
    """
    return html.Div([  # Wrapper div for click handling
        dbc.Card([
            dbc.CardBody([
                # Content section
                dbc.Row([
                    # Main content column
                    dbc.Col([
                        # Title and metadata section
                        html.Div([
                            # Title
                            DashIconify(
                                icon="mdi:file-document-outline",
                                width=22,
                                height=22,
                                className="text-muted me-1 mb-2"
                            ),
                            html.Span(
                                playbook_config.name,
                                className="mb-2 halberd-brand text-xl"
                            ),
                            # Metadata row
                            html.Div([
                                html.Span([
                                    DashIconify(
                                        icon="mdi:account",
                                        width=18,
                                        className="me-1 mb-2 text-muted"
                                    ),
                                    html.Span(
                                        playbook_config.author,
                                        className="text-muted halberd-text me-3"
                                    ),
                                ]),
                                html.Span([
                                    DashIconify(
                                        icon="mdi:calendar",
                                        width=18,
                                        className="me-1 mb-2 text-muted"
                                    ),
                                    html.Span(
                                        playbook_config.creation_date,
                                        className="text-muted halberd-text"
                                    ),
                                ]),
                            ], className="mb-2"),
                        ]),
                        
                        # Description div with fixed height
                        html.Div(
                            html.P(
                                playbook_config.description[:100] + "..." 
                                if len(playbook_config.description) > 100 
                                else playbook_config.description,
                                className="mb-0 text-muted lh-base halberd-typography"
                            ),
                            style={
                                "minHeight": "45px",
                                "maxHeight": "45px",
                                "overflow": "hidden",
                                "textOverflow": "ellipsis"
                            }
                        )
                    ], width=9),

                    # Actions column with fixed width
                    dbc.Col([
                        html.Div([
                            # Primary Action
                            dbc.Button(
                                [
                                    DashIconify(
                                        icon="mdi:play",
                                        width=16,
                                        className="me-2"
                                    ),
                                    "Execute"
                                ],
                                id={"type": "execute-playbook-button", "index": playbook_config.yaml_file},
                                size="sm",
                                className="w-100 mb-2 halberd-button"
                            ),
                            # Secondary Actions
                            dbc.ButtonGroup([
                                dbc.Button(
                                    DashIconify(icon="mdi:pencil", width=16),
                                    id={"type": "edit-playbook-button", "index": playbook_config.yaml_file},
                                    color="light",
                                    size="sm",
                                    title="Edit",
                                    className="px-2"
                                ),
                                dbc.Button(
                                    DashIconify(icon="mdi:calendar", width=16),
                                    id={"type": "open-schedule-win-playbook-button", "index": playbook_config.yaml_file},
                                    color="light",
                                    size="sm",
                                    title="Schedule",
                                    className="px-2"
                                ),
                                dbc.Button(
                                    DashIconify(icon="mdi:download", width=16),
                                    id={"type": "open-export-win-playbook-button", "index": playbook_config.yaml_file},
                                    color="light",
                                    size="sm",
                                    title="Export",
                                    className="px-2"
                                ),
                                dbc.Button(
                                    DashIconify(icon="mdi:delete", width=16),
                                    id={"type": "delete-playbook-button", "index": playbook_config.yaml_file},
                                    color="light",
                                    size="sm",
                                    title="Delete",
                                    className="px-2"
                                ),
                            ], size="sm", className="w-100")
                        ], 
                        className="mx-3 d-flex flex-column halberd-text",
                        # Add zindex to prevent click propagation on buttons
                        style={"zIndex": "1"}),
                    ], 
                    width=3,
                    className="d-flex align-items-center"
                    ),
                ], className="g-0"),
            ], className="p-3"),
        ],
        className="mb-3 halberd-depth-card",
        style={
            "backgroundColor": "#2d2d2d",
        }
        ),
    ],
    # Click handler div
    id={"type": "playbook-card-click", "index": playbook_config.yaml_file},
    className="cursor-pointer hover-highlight",
    # CSS to handle hover and click states
    style={
        "position": "relative",
        "cursor": "pointer",
    }
    )

# Static div for export playbook workflow
export_pb_div = html.Div([
    dbc.Card([
        dbc.CardBody([
            # Mask Config Values Row
            dbc.Row([
                dbc.Col([
                    dbc.Label(
                        "Mask Playbook Config Values", 
                        className="mb-2"
                    ),
                    html.Div([
                        daq.BooleanSwitch(
                            id="export-playbook-mask-param-boolean",
                            on=True,
                            color="var(--brand-red)",  # Halberd red color
                            className="me-2"
                        ),
                        html.Span(
                            "Hide sensitive configuration values", 
                            className="ms-2 align-middle"
                        )
                    ], className="d-flex align-items-center")
                ], width=12, className="mb-3"),
            ]),
            
            # Export Filename Row
            dbc.Row([
                dbc.Col([
                    dbc.Label(
                        "Export File Name (Optional)", 
                        className="mb-2"
                    ),
                    dbc.Input(
                        id="export-playbook-filename-text-input",
                        placeholder="my_playbook_007.yaml",
                        className="bg-halberd-dark halberd-input halberd-text"
                    ),
                    html.Small(
                        "File will be exported as YAML", 
                        className="text-muted mt-2 d-block"
                    )
                ], width=12, className="mb-4"),
            ]),
            
            # Export Button Row
            dbc.Row([
                dbc.Col([
                    dbc.Button(
                        [
                            DashIconify(
                                icon="material-symbols:download-rounded",
                                width=24,
                                height=24,
                                className="me-2"
                            ),
                            "Export Playbook"
                        ],
                        id="export-playbook-button",
                        className="float-end halberd-button",
                        n_clicks=0
                    ),
                ], width=12),
            ]),
        ])
    ], className="bg-halberd-dark border-secondary"),
], className="p-3")

# Static div for playbook schedule workflow
schedule_pb_div = html.Div([
    # Card container
    dbc.Card([
        dbc.CardBody([
            # Execution Time Row
            dbc.Row([
                dbc.Col([
                    dbc.Label("Execution Time *", html_for="set-time-input", className="mb-2"),
                    dbc.Input(
                        id='set-time-input', 
                        type="time", 
                        required=True, 
                        className="bg-halberd-dark halberd-input halberd-text"
                    )
                ], width=12, className="mb-4"),
            ]),
            
            # Date Range Row
            dbc.Row([
                dbc.Col([
                    dbc.Label("Date Range *", html_for="automator-date-range-picker", className="me-2 mb-2"),
                    dcc.DatePickerRange(
                        id='automator-date-range-picker',
                        min_date_allowed=date.today(),
                        max_date_allowed=date(9999, 12, 31),
                        initial_visible_month=date.today(),
                        className="bg-halberd-dark halberd-text"
                    )
                ], width=12, className="mb-4"),
            ]),
            
            # Repeat Switch Row
            dbc.Row([
                dbc.Col([
                    dbc.Label("Repeat Execution", className="mb-2"),
                    html.Div([
                        daq.BooleanSwitch(
                            id='schedule-repeat-boolean',
                            on=False,
                            color="var(--brand-red)",
                            className="me-2"
                        ),
                        html.Span(
                            "Enable repeat execution", 
                            className="ms-2 align-middle"
                        )
                    ], className="d-flex align-items-center")
                ], width=12, className="mb-4"),
            ]),
            
            # Repeat Frequency Row
            dbc.Row([
                dbc.Col([
                    dbc.Label("Repeat Frequency", html_for= "repeat-options-dropdown", className="mb-2"),
                    dcc.Dropdown(
                        id='repeat-options-dropdown',
                        options=[
                            {'label': 'Daily', 'value': 'Daily'},
                            {'label': 'Weekly', 'value': 'Weekly'},
                            {'label': 'Monthly', 'value': 'Monthly'}
                        ],
                        className="bg-halberd-dark halberd-dropdown halberd-text",
                    )
                ], width=12, className="mb-4"),
            ]),
            
            # Schedule Name Row
            dbc.Row([
                dbc.Col([
                    dbc.Label("Schedule Name (Optional)", html_for="schedule-name-input", className="mb-2"),
                    dbc.Input(
                        id='schedule-name-input',
                        placeholder="my_schedule",
                        className="bg-halberd-dark halberd-input halberd-text"
                    )
                ], width=12, className="mb-4"),
            ]),
            
            # Schedule Button Row
            dbc.Row([
                dbc.Col([
                    dbc.Button(
                        [
                            DashIconify(
                                icon="material-symbols:schedule-outline", # Clock icon for schedule
                                width=24,
                                height=24,
                                className="me-2"
                            ),
                            "Schedule Playbook"
                        ],
                        id="schedule-playbook-button",
                        n_clicks=0,
                        className="float-end halberd-button"
                    ),
                ], width=12),
            ]),
        ])
    ], className="bg-halberd-dark halberd-depth-card halberd-text"),
], className="p-3")

def generate_playbook_creator_offcanvas():
    """Generate off-canvas component for creating new playbooks"""
    return [    
                # Playbook metadata form
                dbc.Form([
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Playbook Name *", html_for="pb-name-input-offcanvas"),
                            dbc.Input(
                                type="text",
                                id="pb-name-input-offcanvas",
                                placeholder="Enter playbook name",
                                className="bg-halberd-dark halberd-input halberd-text"
                            )
                        ])
                    ], className="mb-3"),
                    
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Description *", html_for="pb-desc-input-offcanvas"),
                            dbc.Textarea(
                                id="pb-desc-input-offcanvas",
                                placeholder="Enter playbook description",
                                className="bg-halberd-dark halberd-input halberd-text"
                            )
                        ])
                    ], className="mb-3"),
                    
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Author *", html_for="pb-author-input-offcanvas"),
                            dbc.Input(
                                type="text",
                                id="pb-author-input-offcanvas",
                                placeholder="Enter author name",
                                className="bg-halberd-dark halberd-input halberd-text"
                            )
                        ])
                    ], className="mb-3"),
                    
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("References", html_for="pb-refs-input-offcanvas"),
                            dbc.Input(
                                type="text",
                                id="pb-refs-input-offcanvas",
                                placeholder="Enter references (optional)",
                                className="bg-halberd-dark halberd-input halberd-text"
                            )
                        ])
                    ], className="mb-4"),

                    # Steps section
                    html.H4("Playbook Steps", className="mb-3 halberd-brand-heading"),
                    html.Div(id="playbook-steps-container", children=[
                        # Initial step
                        generate_step_form(1, remove_btn=False)
                    ]),
                    
                    # Add step button
                    dbc.Button(
                        [html.I(className="bi bi-plus-lg me-2"), "Add Step"],
                        id="add-playbook-step-button",
                        className="mt-3 mb-4 halberd-button-secondary"
                    ),

                    # Create playbook button
                    dbc.Button(
                        [html.I(className="bi bi-save me-2"), "Create Playbook"],
                        id="create-playbook-offcanvas-button",
                        className="w-100 halberd-button"
                    )
                ])
            ]

def generate_step_form(step_number, remove_btn: bool = True, existing_module=None, existing_wait=None, existing_params_children=None):
    """Generate form elements for a single playbook step
    
    Args:
        step_number: The step number (1-based)
        remove_btn: Whether to show the remove button
        existing_module: Pre-selected module ID (optional)
        existing_wait: Pre-filled wait time value (optional)
        existing_params_children: Pre-filled parameters container children (optional)
    """
    step_form = dbc.Card([
        dbc.CardHeader([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.I(
                            className="fas fa-layer-group me-2", 
                            style={
                                "color": "#dc3545", 
                                "fontSize": "1rem"
                            }
                        ),
                        html.Span(
                            f"Step {step_number}", 
                            className="halberd-brand",
                            style={
                                "fontSize": "1rem",
                                "fontWeight": "700",
                                "color": "#ffffff"
                            }
                        )
                    ], className="d-flex align-items-center")
                ], width=10),
                 generate_remove_btn({"index": step_number}) if remove_btn else None
            ], className="align-items-center")
        ], style={
            "background": "linear-gradient(135deg, rgba(220, 53, 69, 0.15) 0%, rgba(108, 117, 125, 0.15) 100%)",
            "borderBottom": "2px solid rgba(220, 53, 69, 0.3)",
            "borderRadius": "8px 8px 0 0"
        }),
        dbc.CardBody([
            # Module Selection Row
            dbc.Row([
                dbc.Col([
                    dbc.Label(
                        [
                            html.I(className="fas fa-cube me-2", style={"color": "#6c757d"}),
                            "Module *"
                        ],
                        className="halberd-text mb-2 d-block",
                        style={"fontWeight": "600"}
                    ),
                    dcc.Dropdown(
                        id={"type": "step-module-dropdown", "index": step_number},
                        options=[
                            {"label": technique().name, "value": tid}
                            for tid, technique in TechniqueRegistry.list_techniques().items()
                        ],
                        value=existing_module,  # Pre-populate if provided
                        placeholder="Select technique module...",
                        className="halberd-dropdown",
                        style={
                            "background": "rgba(33, 37, 41, 0.8)",
                            "border": "2px solid rgba(108, 117, 125, 0.3)",
                            "borderRadius": "8px"
                        }
                    )
                ])
            ], className="mb-4"),
            
            # Dynamic parameters section with header
            html.Div([
                html.Div([
                    html.I(className="fas fa-sliders-h me-2", style={"color": "#6c757d", "fontSize": "0.9rem"}),
                    html.Span("Parameters", style={"fontSize": "0.9rem", "fontWeight": "600"})
                ], className="text-muted mb-3"),
                html.Div(
                    existing_params_children if existing_params_children is not None else [],  # Pre-populate if provided
                    id={"type": "step-params-container", "index": step_number},
                    style={
                        "minHeight": "50px",
                        "padding": "10px",
                        "backgroundColor": "rgba(33, 37, 41, 0.4)",
                        "borderRadius": "8px",
                        "border": "1px solid rgba(108, 117, 125, 0.2)"
                    }
                )
            ], className="mb-4"),

            # Wait Time Row
            dbc.Row([
                dbc.Col([
                    dbc.Label(
                        [
                            html.I(className="fas fa-hourglass-end me-2", style={"color": "#6c757d"}),
                            "Wait After Step (seconds)"
                        ],
                        className="halberd-text mb-2 d-block",
                        style={"fontWeight": "600"}
                    ),
                    dbc.Input(
                        type="number",
                        id={"type": "step-wait-input", "index": step_number},
                        value=existing_wait,  # Pre-populate if provided
                        placeholder="0",
                        min=0,
                        className="halberd-input",
                        style={
                            "background": "rgba(33, 37, 41, 0.8)",
                            "border": "2px solid rgba(108, 117, 125, 0.3)",
                            "borderRadius": "8px",
                            "color": "#ffffff",
                            "padding": "12px 16px"
                        }
                    )
                ], width=12)
            ], className="mb-0"),
        ], style={
            "padding": "24px",
            "backgroundColor": "rgba(33, 37, 41, 0.5)"
        })
    ], className="mb-3 halberd-depth-card", style={
        "border": "1px solid rgba(220, 53, 69, 0.2)",
        "borderRadius": "12px"
    })
    return step_form

def generate_playbook_editor_form():
    """Generate the editor form structure (metadata inputs, steps container, buttons)"""
    return dbc.Form([
        dbc.Row([
            dbc.Col([
                dbc.Label("Playbook Name *", html_for="pb-name-input-editor"),
                dbc.Input(
                    type="text",
                    id="pb-name-input-editor",
                    placeholder="Enter playbook name",
                    className="bg-halberd-dark halberd-input halberd-text"
                )
            ])
        ], className="mb-3"),
        
        dbc.Row([
            dbc.Col([
                dbc.Label("Description *", html_for="pb-desc-input-editor"),
                dbc.Textarea(
                    id="pb-desc-input-editor",
                    placeholder="Enter playbook description",
                    className="bg-halberd-dark halberd-input halberd-text"
                )
            ])
        ], className="mb-3"),
        
        dbc.Row([
            dbc.Col([
                dbc.Label("Author *", html_for="pb-author-input-editor"),
                dbc.Input(
                    type="text",
                    id="pb-author-input-editor",
                    placeholder="Enter author name",
                    className="bg-halberd-dark halberd-input halberd-text"
                )
            ])
        ], className="mb-3"),
        
        dbc.Row([
            dbc.Col([
                dbc.Label("References", html_for="pb-refs-input-editor"),
                dbc.Input(
                    type="text",
                    id="pb-refs-input-editor",
                    placeholder="Enter references (optional)",
                    className="bg-halberd-dark halberd-input halberd-text"
                )
            ])
        ], className="mb-4"),

        # Steps section
        html.Div([
            html.H4("Playbook Steps", className="mb-3 halberd-brand-heading"),
            html.Div(id="playbook-steps-editor-container"),
            
            # Add step button
            dbc.Button(
                [html.I(className="bi bi-plus-lg me-2"), "Add Step"],
                id="add-playbook-step-editor-button",
                color="secondary",
                className="mt-3 mb-4"
            ),
        ]),

        # Update playbook button
        dbc.Button(
            [html.I(className="bi bi-save me-2"), "Update Playbook"],
            id="update-playbook-editor-button",
            className="w-100 halberd-button"
        )
    ])

def generate_playbook_editor_offcanvas():
    """Generate empty editor offcanvas container - children will be populated by callback when opened"""
    return dbc.Offcanvas(
        [],  # Empty children - will be populated when opened
        id="playbook-editor-offcanvas",
        title= html.H3("Playbook Editor"),
        is_open=False,
        placement="end",
        style={
            "width": "50%",
            "max-width": "none"
        },
        className="bg-halberd-dark halberd-text halberd-offcanvas",
        backdropClassName="halberd-offcanvas-backdrop"
        )

# The old local parameter-input generator was removed in favor of the
# centralized `generate_attack_technique_config` helper located in
# `core.Functions.generate_attack_technique_config`.
#
# Rationale:
# - The central helper produces inputs with the canonical IDs
#   ("attack-technique-config") that the rest of the callbacks rely on
#   (pattern-matching States/Inputs).
# - It supports existing values, upload handling, and mode-specific
#   rendering for both "attack" and "automator" contexts.
#
# If page-local customization is required later, provide a thin wrapper
# that delegates to `generate_attack_technique_config` to avoid duplication.

def create_execution_progress_offcanvas():
    """Creates the execution progress off-canvas"""
    return dbc.Offcanvas([
        # Info message
        dbc.Alert([
            DashIconify(icon="mdi:information", className="me-2"),
            "You can close this window and return anytime to check progress. ",
            "Click the 'View Progress' button to reopen.",
        ], 
        color="primary", 
        className="mb-4"
        ),
        
        # Progress content
        html.Div(
            id="playbook-execution-progress",
            className="mb-4"
        ),
        
        # Interval for updates
        dcc.Interval(
            id="execution-interval",
            interval=1000,
            disabled=True
        ),
    ],
    id="execution-progress-offcanvas",
    title=html.H3("Execution Progress"),
    placement="end",
    is_open=False,
    style={"width": "50%"},
    className="bg-halberd-dark halberd-offcanvas",
    backdropClassName="halberd-offcanvas-backdrop",
    scrollable=True
    )

def create_step_progress_card(step_number, module_name, status=None, is_active=False, message=None):
    """Creates a card showing execution status for a single playbook step"""
    # Define status icon and color
    if is_active:
        icon = DashIconify(
            icon="mdi:progress-clock",
            width=24,
            className="text-primary animate-spin"
        )
        status_color = "text-light"
    elif status == "success":
        icon = DashIconify(
            icon="mdi:check-circle",
            width=24,
            className="text-success"
        )
        status_color = "text-success"
    elif status == "failed":
        icon = DashIconify(
            icon="mdi:alert-circle",
            width=24,
            className="text-danger"
        )
        status_color = "text-danger"
    else:
        icon = DashIconify(
            icon="mdi:circle-outline",
            width=24,
            className="text-gray-400"
        )
        status_color = "text-muted"

    return dbc.Card([
        dbc.CardBody([
            dbc.Row([
                dbc.Col(icon, width=1),
                dbc.Col([
                    dbc.Row([
                        dbc.Col(
                            html.H6(
                                f"Step {step_number}: {module_name}",
                                className="mb-0 halberd-text"
                            ),
                            width=9
                        ),
                        dbc.Col(
                            html.Span(
                                status.title() if status else "Pending",
                                className=status_color
                            ),
                            width=3,
                            className="text-end"
                        )
                    ]),
                    html.Small(
                        message,
                        className="text-danger"
                    ) if message else None,
                ], width=11)
            ], className="align-items-center halberd-text")
        ])
    ], className=f"mb-2 {'border-primary' if is_active else ''} bg-halberd-dark")

# Create Automator layout
layout = create_playbook_manager_layout

# Callbacks
'''Callback to generate attack sequence visualization in Automator'''
@callback(
    Output("playbook-visualization-container", "children"),
    [Input({"type": "playbook-card-click", "index": ALL}, "n_clicks")],
    prevent_initial_call=True
)
def update_visualization(n_clicks):
    """Update the visualization when a playbook is selected"""
    if not callback_context.triggered:
        raise PreventUpdate
    
    # Get the triggered component's ID
    triggered = callback_context.triggered[0]
    prop_id = json.loads(triggered['prop_id'].rsplit('.',1)[0])
    
    if triggered['value'] is None:  # No clicks yet
        raise PreventUpdate
        
    playbook_id = prop_id['index']
    
    try:
        pb_config = Playbook(playbook_id)
        # Return both the visualization and some playbook info
        return html.Div([
            
            dbc.Card([
                dbc.CardHeader(
                    html.Div(
                        f"Playbook : {pb_config.name}", 
                        className="mb-0 halberd-brand text-2xl"
                    )
                ),
                dbc.CardBody([
                    html.H5("Description:", className="mb-2 halberd-typography"),
                    html.P(pb_config.description, className="mb-3 halberd-text"),
                    dbc.Row(
                        [
                            dbc.Col(html.P(f"Total Steps: {pb_config.steps}", className="mb-1 halberd-depth-card"), md=4),
                            dbc.Col(html.P(f"Author: {pb_config.author}", className="mb-1 halberd-depth-card"), md=4),
                            dbc.Col(html.P(f"Created: {pb_config.creation_date}", className="mb-1 halberd-depth-card"), md=4)
                        ],
                        style={
                            'textAlign': 'center'
                        }
                    )
                ])
            ], className="bg-halberd-dark halberd-depth-card"),
            html.Div(playbook_viz_generator(pb_config.name), className="mb-3"),
        ])
    except Exception as e:
        return html.Div([
            html.H4("Error Loading Visualization", className="text-danger"),
            html.P(str(e), className="text-muted")
        ], className="p-3")

'''Callback to execute attack sequence in automator view'''
@callback(
    Output("execution-progress-offcanvas", "is_open", allow_duplicate=True),
    Output("app-notification", "is_open", allow_duplicate=True),
    Output("app-notification", "children", allow_duplicate=True),
    Output("app-error-display-modal", "is_open", allow_duplicate=True),
    Output("app-error-display-modal-body", "children", allow_duplicate=True),
    Output("selected-playbook-data", "data", allow_duplicate=True),
    Output("execution-interval", "disabled", allow_duplicate=True),
    Input({'type': 'execute-playbook-button', 'index': ALL}, 'n_clicks'),
    prevent_initial_call=True
)
def execute_playbook_callback(n_clicks):
    """Execute playbook and initialize progress tracking"""
    if not any(n_clicks):
        raise PreventUpdate
        
    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate
        
    # Get clicked playbook
    button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
    playbook_file = eval(button_id)['index']
    
    try:
        # Execute playbook in background thread
        def execute_playbook():
            playbook = Playbook(playbook_file)
            playbook.execute()
            
        execution_thread = threading.Thread(target=execute_playbook)
        execution_thread.daemon = True
        execution_thread.start()
        
        return True, True, "Playbook Execution Started", False, "", playbook_file, False
        
    except PlaybookError as e:
        error_msg = f"Playbook Execution Failed: {str(e.message)}"
        return False, False, "", True, error_msg, None, True
    except Exception as e:
        error_msg = f"Unexpected Error: {str(e)}"
        return False, False, "", True, error_msg, None, True

'''Callback to open attack scheduler off canvas'''
@callback(
        Output(component_id = "automator-offcanvas", component_property = "is_open", allow_duplicate= True), 
        Output(component_id = "automator-offcanvas", component_property = "title", allow_duplicate= True),
        Output(component_id = "automator-offcanvas", component_property = "children", allow_duplicate= True),
        Output(component_id="selected-playbook-data", component_property="data", allow_duplicate= True),
        Input({'type': 'open-schedule-win-playbook-button', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True
)
def toggle_pb_schedule_canvas_callback(n_clicks):
    if not any(n_clicks):
        raise PreventUpdate
    
    # Find which button was clicked
    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    # Extract playbook name from context
    button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
    selected_pb_name = eval(button_id)['index']

    return True, html.H3(["Schedule Playbook"]), schedule_pb_div, selected_pb_name

'''Callback to create new automator schedule'''
@callback(
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), 
        Output(component_id = "automator-offcanvas", component_property = "is_open", allow_duplicate=True),
        Output(component_id = "automator-offcanvas", component_property = "children", allow_duplicate=True),
        State(component_id="selected-playbook-data", component_property="data"),
        State(component_id = "set-time-input", component_property = "value"), 
        State(component_id = "automator-date-range-picker", component_property = "start_date"), 
        State(component_id = "automator-date-range-picker", component_property = "end_date"), 
        State(component_id = "schedule-repeat-boolean", component_property = "on"), 
        State(component_id = "repeat-options-dropdown", component_property = "value"), 
        State(component_id = "schedule-name-input", component_property = "value"), 
        Input(component_id = "schedule-playbook-button", component_property = "n_clicks"), 
        prevent_initial_call=True)
def create_new_schedule_callback(selected_pb_data, execution_time, start_date, end_date, repeat_flag, repeat_frequency, schedule_name, n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    
    if selected_pb_data == None:
        raise PreventUpdate
    
    playbook_id = selected_pb_data
    # Create new schedule
    AddNewSchedule(schedule_name, playbook_id, start_date, end_date, execution_time, repeat_flag, repeat_frequency)

    # Send notification after new schedule is created and close scheduler off canvas
    return True, "Playbook Scheduled", False, []

'''Callback to export playbook'''
@callback(
        Output(component_id = "app-download-sink", component_property = "data", allow_duplicate = True), 
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True),
        Output(component_id = "app-error-display-modal", component_property = "is_open", allow_duplicate=True),
        Output(component_id = "app-error-display-modal-body", component_property = "children", allow_duplicate=True),  
        State(component_id="selected-playbook-data", component_property="data"),
        State(component_id = "export-playbook-mask-param-boolean", component_property = "on"),
        State(component_id = "export-playbook-filename-text-input", component_property = "value"),
        Input(component_id = "export-playbook-button", component_property = "n_clicks"), 
        prevent_initial_call=True)
def export_playbook_callback(selected_pb_data, mask_param, export_file_name, n_clicks):
    if n_clicks == 0:
        raise PreventUpdate

    playbook_file = selected_pb_data
    playbook = Playbook(playbook_file)
    
    if not export_file_name:
        export_file_base_name = "Halberd_Playbook" # Set default file name
        export_file_name = export_file_base_name+"-"+(playbook.name).replace(" ", "_")+".yml"
    
    # Export playbook
    playbook_export_file_path = playbook.export(export_file = export_file_name, include_params=not(mask_param))

    # Download playbook and send app notification
    return dcc.send_file(playbook_export_file_path), True, "Playbook Exported", False, ""

'''Callback to import playbook'''
@callback(
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True),
        Output(component_id = "app-error-display-modal", component_property = "is_open", allow_duplicate=True),
        Output(component_id = "app-error-display-modal-body", component_property = "children", allow_duplicate=True), 
        Output('playbook-list-container', 'children', allow_duplicate=True),
        Output("playbook-stats", "children", allow_duplicate=True),
        Input(component_id = 'import-pb-button', component_property = 'n_clicks'), 
        Input(component_id = 'upload-playbook', component_property = 'contents'), 
        prevent_initial_call=True)
def import_playbook_callback(n_clicks, file_contents):
    if n_clicks == 0:
        raise PreventUpdate

    if file_contents:
        try:
            # Import playbook
            Playbook.import_playbook(file_contents)

            # Refresh the playbook list
            playbooks = GetAllPlaybooks()
            playbook_items = []
            
            for pb_file in playbooks:
                try:
                    pb_config = Playbook(pb_file)
                    # Apply search filter if query exists
                    playbook_items.append(create_playbook_item(pb_config))
                except Exception as e:
                    print(f"Error loading playbook {pb_file}: {str(e)}")
            
            # Generate stats
            stats = get_playbook_stats()
            stats_text = (f"{stats['total_playbooks']} playbooks loaded • "
                        f"Last sync: {stats['last_sync'].strftime('%I:%M %p') if stats['last_sync'] else 'never'}")

            # Import success - display notification and update playbook list    
            return True, "Playbook Imported", False, "", playbook_items, stats_text
        except Exception as e:
            # Display error in modal pop up
            return False, "", True, str(e), no_update, no_update
    else:
        raise PreventUpdate
    
'''Callback to open playbook creator off canvas'''
@callback(
        Output(component_id = "automator-offcanvas", component_property = "is_open", allow_duplicate= True), 
        Output(component_id = "automator-offcanvas", component_property = "title", allow_duplicate= True),
        Output(component_id = "automator-offcanvas", component_property = "children", allow_duplicate= True),
        Input(component_id = 'open-creator-win-playbook-button', component_property= 'n_clicks'),
        prevent_initial_call=True
)
def toggle_pb_creator_canvas_callback(n_clicks):
    if n_clicks:
        return True, [html.H3("Create New Playbook")], generate_playbook_creator_offcanvas()

    raise PreventUpdate

'''Callback to create new playbook'''
@callback(
        Output(component_id = "playbook-creator-modal", component_property = "is_open", allow_duplicate=True),  
        Output(component_id = "app-notification", component_property = "is_open", allow_duplicate=True), 
        Output(component_id = "app-notification", component_property = "children", allow_duplicate=True), 
        Output(component_id = "app-error-display-modal", component_property = "is_open", allow_duplicate=True),
        Output(component_id = "app-error-display-modal-body", component_property = "children", allow_duplicate=True),
        State(component_id = "pb-name-input", component_property = "value"), 
        State(component_id = "pb-desc-input", component_property = "value"), 
        State(component_id = "pb-author-input", component_property = "value"), 
        State(component_id = "pb-refs-input", component_property = "value"), 
        Input(component_id = "create-playbook-button", component_property = "n_clicks"), prevent_initial_call=True
    )
def create_new_pb_callback(pb_name, pb_desc, pb_author, pb_references, n_clicks):
    if n_clicks == 0:
        raise PreventUpdate
    
    try:
        new_playbook = Playbook.create_new(
            name= pb_name,
            author= pb_author,
            description= pb_desc,
            references=[pb_references]
        )
        return False, True, f"New Playbook Created : {new_playbook.name}", False, ""
    except Exception as e:
        return True, False, "", True, str(e)
    
'''Callback to display technique info from playbook node in modal'''
@callback(
        Output(component_id = "app-technique-info-display-modal-body", component_property = "children"),
        Output(component_id = "app-technique-info-display-modal", component_property = "is_open"),
        Input(component_id = "auto-attack-sequence-cytoscape-nodes", component_property = "tapNodeData"),
        [State(component_id = "app-technique-info-display-modal", component_property = "is_open")], 
        prevent_initial_call=True
    )
def toggle_t_info_modal_callback(data, is_open):
    if data:
        # Extract module_id from node label
        if data['label'] != "None":
            info = data['info']
        else:
            raise PreventUpdate
        
        if info == "time":
            # Display time gap
            wait_time = data['label']
            return [html.B(f"Time Gap : {wait_time} seconds")], True
        else:
            # Display module info
            pb_step_info = data['info']
            step_data = next(iter(pb_step_info.items()))
            module_id = step_data[1]['Module']
            return generate_technique_info(module_id), not is_open
    else:
        raise PreventUpdate

'''Callback to open/close add to playbook modal on Attack page'''
@callback(
    Output(component_id = "add-to-playbook-modal", component_property = "is_open"),
    [
        Input(component_id = "open-add-to-playbook-modal-button", component_property = "n_clicks"), 
        Input(component_id = "close-add-to-playbook-modal-button", component_property = "n_clicks"), 
        Input(component_id = "confirm-add-to-playbook-modal-button", component_property = "n_clicks")
    ],
    [State(component_id = "add-to-playbook-modal", component_property = "is_open")],
    prevent_initial_call=True
)
def toggle_add_to_pb_modal_callback(n1, n2, n3, is_open):
    if n1 or n2 or n3:
        return not is_open
    return is_open

'''[Automator] Callback to generate/update playbook list in automator'''
@callback(
    Output("playbook-list-container", "children"),
    Output("playbook-stats", "children"),
    Input("playbook-search", "value"),
)
def update_playbook_list_callback(search_query):
    """Update the playbook list and stats based on search query"""
    # Get all available playbooks on system
    playbooks = GetAllPlaybooks()
    
    # Generate stats
    stats = get_playbook_stats()
    stats_text = (f"{stats['total_playbooks']} playbooks loaded • "f"Last sync: {stats['last_sync'].strftime('%I:%M %p') if stats['last_sync'] else 'never'}")
    
    # If no playbooks found on system
    if not playbooks:
        empty_playbook_list_div = html.Div(
            children=[
                html.Div([
                    DashIconify(
                        icon="mdi:information-outline", #Information icon
                        width=48,
                        height=48,
                        className="text-muted mb-3"
                    ),
                    html.P(
                        "Create or Import a playbook", # Default message when no playbook is selected
                        className="halberd-text text-muted")
                ], className="text-center")
            ],
            className="d-flex justify-content-center align-items-center",
            style={'padding':'20px'}
        )
        return empty_playbook_list_div, stats_text
    
    # Initialize list to store playbook items
    playbook_items = []
    
    for pb_file in playbooks:
        try:
            pb_config = Playbook(pb_file)
            # Apply search filter if query exists
            if search_query and search_query.lower() not in pb_config.name.lower():
                continue
            playbook_items.append(create_playbook_item(pb_config))
        except Exception as e:
            print(f"Error loading playbook {pb_file}: {str(e)}")

    return playbook_items, stats_text
    
'''Callback to delete playbook from automator'''
@callback(
    Output('playbook-list-container', 'children', allow_duplicate=True),
    Output("playbook-stats", "children", allow_duplicate=True),
    Input({'type': 'delete-playbook-button', 'index': ALL}, 'n_clicks'),
    prevent_initial_call=True
)
def delete_playbook(n_clicks):
    """Handles playbook deletion"""
    if not any(n_clicks):
        return no_update
    
    # Find which button was clicked
    ctx = callback_context
    if not ctx.triggered:
        return no_update
    
    button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
    playbook_file = eval(button_id)['index']

    try:
        # Delete the playbook file
        os.remove(os.path.join(AUTOMATOR_PLAYBOOKS_DIR, playbook_file))
        
        # Refresh the playbook list
        playbooks = GetAllPlaybooks()

        # Generate stats
        stats = get_playbook_stats()
        stats_text = (f"{stats['total_playbooks']} playbooks loaded • "f"Last sync: {stats['last_sync'].strftime('%I:%M %p') if stats['last_sync'] else 'never'}")

        if not playbooks:
            empty_playbook_list_div = html.Div(
                children=[
                    html.Div([
                        DashIconify(
                            icon="mdi:information-outline", #Information icon
                            width=48,
                            height=48,
                            className="text-muted mb-3"
                        ),
                        html.P("Create or Import a playbook", # Default message when no playbook is selected
                                className="text-muted")
                    ], className="text-center")
                ],
                className="d-flex justify-content-center align-items-center",
                style={'padding':'20px'}
            )
            return empty_playbook_list_div, stats_text

        # Initialize list to store playbook items
        playbook_items = []
        
        for pb_file in playbooks:
            try:
                pb_config = Playbook(pb_file)
                # Apply search filter if query exists
                playbook_items.append(create_playbook_item(pb_config))
            except Exception as e:
                print(f"Error loading playbook {pb_file}: {str(e)}")
        
        
        
        return playbook_items, stats_text
    except Exception as e:
        print(f"Error deleting playbook {playbook_file}: {str(e)}")
        return no_update
    
'''Callback to close the playbook information modal'''
@callback(
    Output("automator-playbook-info-display-modal", "is_open", allow_duplicate=True),
    Input("close-automator-playbook-info-display-modal", "n_clicks"),
    State("automator-playbook-info-display-modal", "is_open"),
    prevent_initial_call=True
)
def close_pb_info_modal_callback(n_clicks, is_open):
    if n_clicks:
        return False
    return is_open

'''Callback to open playbook export modal'''
@callback(
        Output(component_id = "automator-offcanvas", component_property = "is_open", allow_duplicate= True), 
        Output(component_id = "automator-offcanvas", component_property = "title", allow_duplicate= True),
        Output(component_id = "automator-offcanvas", component_property = "children", allow_duplicate= True),
        Output(component_id="selected-playbook-data", component_property="data", allow_duplicate= True),
        Input({'type': 'open-export-win-playbook-button', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True
)
def toggle_pb_export_canvas_callback(n_clicks):
    if not any(n_clicks):
        raise PreventUpdate
    
    # Find which button was clicked
    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    # Extract playbook name from context
    button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
    selected_pb_name = eval(button_id)['index']
    
    return True, [html.H3("Export Playbook")], export_pb_div, selected_pb_name

'''Create new playbook functionality callbacks'''
'''[Playbook Creator] Callback to generate/update parameter fields from selected technique'''
@callback(
    Output({"type": "step-params-container", "index": MATCH}, "children"),
    Input({"type": "step-module-dropdown", "index": MATCH}, "value"),
    prevent_initial_call=True
)
def update_step_parameters(module_id):
    """Update parameter fields based on selected module"""
    if not module_id:
        return []
    # Determine which step triggered this MATCH callback so we can include
    # the step index in generated parameter IDs (avoids mixing params across steps)
    ctx = callback_context
    if not ctx.triggered:
        return []

    triggered_id = json.loads(ctx.triggered[0]["prop_id"].rsplit('.', 1)[0])
    step_index = triggered_id.get("index")

    technique_config = generate_attack_technique_config(module_id, mode="automator", step_index=step_index, id_type="creator")
    return technique_config
    

'''Callback to display selected filename in automator playbook parameters (creator mode)'''
@callback(
    Output({"type": "attack-technique-config-filename-display-creator", "param": MATCH, "step": MATCH}, "children"),
    Input({"type": "attack-technique-config-creator", "technique": ALL, "param": MATCH, "step": MATCH}, "contents"),
    State({"type": "attack-technique-config-creator", "technique": ALL, "param": MATCH, "step": MATCH}, "filename"),
    prevent_initial_call=False
)
def display_uploaded_file_names_automator_creator(contents, filename):
    if not contents:
        return "No file(s) selected"
    
    if filename:
        # filename from dcc.Upload is always a list like ['file.txt']
        if isinstance(filename, list):
            # Filter out None/empty values and extract just the filenames
            valid_files = [str(f) for f in filename if f]
            if valid_files:
                return f"Selected: {', '.join(valid_files)}"
            return "No file(s) selected"
        else:
            # Single string (unlikely with dcc.Upload)
            return f"Selected: {str(filename)}"
    else:
        return "No file(s) selected"

'''Callback to display selected filename in automator playbook parameters (editor mode)'''
@callback(
    Output({"type": "attack-technique-config-filename-display-editor", "param": MATCH, "step": MATCH}, "children"),
    Input({"type": "attack-technique-config-editor", "technique": ALL, "param": MATCH, "step": MATCH}, "contents"),
    State({"type": "attack-technique-config-editor", "technique": ALL, "param": MATCH, "step": MATCH}, "filename"),
    prevent_initial_call=False
)
def display_uploaded_file_names_automator_editor(contents, filename):
    if not contents:
        return "No file(s) selected"
    
    if filename:
        # filename from dcc.Upload is always a list like ['file.txt']
        if isinstance(filename, list):
            # Filter out None/empty values and extract just the filenames
            valid_files = [str(f) for f in filename if f]
            if valid_files:
                return f"Selected: {', '.join(valid_files)}"
            return "No file(s) selected"
        else:
            # Single string (unlikely with dcc.Upload)
            return f"Selected: {str(filename)}"
    else:
        return "No file(s) selected"

'''[Playbook Creator] Callback to add a new step in playbook'''
@callback(
    Output("playbook-steps-container", "children"),
    Input("add-playbook-step-button", "n_clicks"),
    State("playbook-steps-container", "children"),
    State({"type": "step-module-dropdown", "index": ALL}, "value"),
    State({"type": "step-wait-input", "index": ALL}, "value"),
    State({"type": "attack-technique-config-creator", "step": ALL, "technique": ALL, "param": ALL}, "value"),
    State({"type": "attack-technique-config-creator", "step": ALL, "technique": ALL, "param": ALL}, "id"),
    prevent_initial_call=True
)
def add_playbook_step(n_clicks, current_steps, module_values, wait_values, param_values, param_ids):
    """Add a new step form to the playbook creator"""
    # Only act when the add button was clicked
    if not n_clicks:
        raise PreventUpdate

    # current_steps may contain falsy entries (e.g., None) if some
    # children were conditionally omitted. Filter them out.
    if not current_steps:
        current_count = 0
    else:
        # Filter out any falsy children (None) that can appear when
        # a step's remove-button is conditionally omitted.
        current_count = sum(1 for s in current_steps if s)

    new_step_number = current_count + 1

    # Build a map of parameter values by step number
    params_by_step = {}
    if param_ids and param_values:
        for idx, param_id in enumerate(param_ids):
            step_num = param_id.get("step")
            param_name = param_id.get("param")
            if step_num and param_name:
                if step_num not in params_by_step:
                    params_by_step[step_num] = {}
                params_by_step[step_num][param_name] = param_values[idx] if idx < len(param_values) else None

    # Recreate the step forms with existing data to ensure numbering and IDs remain consistent
    remaining_steps = []
    for i in range(current_count):
        # Get existing values from the pattern-matched States
        existing_module = module_values[i] if i < len(module_values) else None
        existing_wait = wait_values[i] if i < len(wait_values) else None
        
        # Get existing parameter values for this step (old step number is i+1)
        old_step_num = i + 1
        existing_param_values = params_by_step.get(old_step_num, {})
        
        # Regenerate params with correct step index if module is selected
        if existing_module:
            existing_params = generate_attack_technique_config(
                existing_module, 
                mode="automator", 
                existing_values=existing_param_values,  # Pass existing values
                step_index=i + 1,  # Use the NEW step number
                id_type="creator"
            )
        else:
            existing_params = None
        
        # Regenerate with new index (1-based) but existing values
        step_form = generate_step_form(
            i + 1, 
            remove_btn=True,
            existing_module=existing_module,
            existing_wait=existing_wait,
            existing_params_children=existing_params
        )
        remaining_steps.append(step_form)
    
    # Add the new empty step at the end
    new_step = generate_step_form(new_step_number, remove_btn=True)
    remaining_steps.append(new_step)

    return remaining_steps

'''[Playbook Creator] Callback to remove a step from playbook'''
@callback(
    Output("playbook-steps-container", "children", allow_duplicate=True),
    Input({"type": "remove-step-button", "index": ALL}, "n_clicks"),
    State("playbook-steps-container", "children"),
    State({"type": "step-module-dropdown", "index": ALL}, "value"),
    State({"type": "step-wait-input", "index": ALL}, "value"),
    State({"type": "attack-technique-config-creator", "step": ALL, "technique": ALL, "param": ALL}, "value"),
    State({"type": "attack-technique-config-creator", "step": ALL, "technique": ALL, "param": ALL}, "id"),
    prevent_initial_call=True
)
def remove_playbook_step(n_clicks, current_steps, module_values, wait_values, param_values, param_ids):
    """Remove a step from the playbook creator"""
    if not any(n_clicks):
        raise PreventUpdate
    
    # Find which button was clicked
    ctx = dash.callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    button_id = json.loads(ctx.triggered[0]["prop_id"].rsplit(".")[0])
    step_to_remove = button_id["index"]

    # Remove the step by index and renumber remaining steps
    # step_to_remove can be int or str depending on JSON decoding; normalize to int
    try:
        step_index = int(step_to_remove) - 1
    except Exception:
        raise PreventUpdate

    # Validate index and current_steps
    if not current_steps or step_index < 0 or step_index >= len(current_steps):
        raise PreventUpdate

    # Filter out falsy entries
    valid_steps_count = sum(1 for s in current_steps if s)
    
    # Build a map of parameter values by step number
    params_by_step = {}
    if param_ids and param_values:
        for idx, param_id in enumerate(param_ids):
            step_num = param_id.get("step")
            param_name = param_id.get("param")
            if step_num and param_name:
                if step_num not in params_by_step:
                    params_by_step[step_num] = {}
                params_by_step[step_num][param_name] = param_values[idx] if idx < len(param_values) else None
    
    # Build list of remaining step indices and their values
    remaining_steps = []
    new_step_num = 1
    
    for i in range(valid_steps_count):
        if i != step_index:
            # Get existing values from the pattern-matched States
            existing_module = module_values[i] if i < len(module_values) else None
            existing_wait = wait_values[i] if i < len(wait_values) else None
            
            # Get existing parameter values for this step (old step number is i+1)
            old_step_num = i + 1
            existing_param_values = params_by_step.get(old_step_num, {})
            
            # Regenerate params with correct step index if module is selected
            if existing_module:
                existing_params = generate_attack_technique_config(
                    existing_module, 
                    mode="automator", 
                    existing_values=existing_param_values,  # Pass existing values
                    step_index=new_step_num,  # Use the NEW step number
                    id_type="creator"
                )
            else:
                existing_params = None
            
            # Determine if remove button should be shown
            # (will be true for all steps since we'll have at least 1 after removal)
            show_remove_btn = (valid_steps_count - 1) > 1
            
            # Regenerate with new sequential index but existing values
            step_form = generate_step_form(
                new_step_num, 
                remove_btn=show_remove_btn,
                existing_module=existing_module,
                existing_wait=existing_wait,
                existing_params_children=existing_params
            )
            remaining_steps.append(step_form)
            new_step_num += 1

    return remaining_steps

'''[Playbook Creator] Callback to create a new playbook from offcanvas configuration'''
@callback(
    Output("app-notification", "is_open", allow_duplicate=True),
    Output("app-notification", "children", allow_duplicate=True),
    Output("app-error-display-modal", "is_open", allow_duplicate=True),
    Output("app-error-display-modal-body", "children", allow_duplicate=True),
    Output("automator-offcanvas", "is_open", allow_duplicate=True),
    Output("automator-offcanvas", "children", allow_duplicate=True),
    Output('playbook-list-container', 'children', allow_duplicate=True),
    Output("playbook-stats", "children", allow_duplicate=True),
    Input("create-playbook-offcanvas-button", "n_clicks"),
    [
        State("pb-name-input-offcanvas", "value"),
        State("pb-desc-input-offcanvas", "value"),
        State("pb-author-input-offcanvas", "value"),
        State("pb-refs-input-offcanvas", "value"),
        State({"type": "step-module-dropdown", "index": ALL}, "value"),
        State({"type": "step-wait-input", "index": ALL}, "value"),
    # Pattern-match all technique-config inputs but include the 'step' key
    # so we can group param values by step.
    State({"type": "attack-technique-config-creator", "step": ALL, "technique": ALL, "param": ALL}, "value"),
    State({"type": "attack-technique-config-creator", "step": ALL, "technique": ALL, "param": ALL}, "id"),
    State({"type": "attack-technique-config-creator", "step": ALL, "technique": ALL, "param": ALL}, "contents"),
    State({"type": "attack-technique-config-creator", "step": ALL, "technique": ALL, "param": ALL}, "filename")
    ],
    prevent_initial_call=True
)
def create_playbook_from_offcanvas(n_clicks, name, desc, author, refs, modules, waits, param_values, param_ids, file_contents, file_names):
    """Create a new playbook from the off-canvas form data"""
    if not n_clicks:
        raise PreventUpdate
    
    try:
        # Validate required fields
        if not all([name, desc, author]):
            raise ValueError("Please fill in all required fields")
        
        if not any(modules):
            raise ValueError("At least one step is required")
        
        # Create new playbook
        new_playbook = Playbook.create_new(
            name=name,
            author=author,
            description=desc,
            references=[refs] if refs else None
        )
        
        # Build a nested parameter map keyed by step number to avoid mixing
        # parameters from different step forms. Each param_id contains a
        # 'step' key (added when generating inputs) which we use to group values.
        params_by_step = {}
        if param_ids:
            for idx, pid in enumerate(param_ids):
                # pid is a dict like {"type":"attack-technique-config","step": X, "technique": T, "param": P}
                step_key = pid.get('step')
                try:
                    step_key = int(step_key) if step_key is not None else None
                except Exception:
                    # keep as-is if not convertable
                    pass

                if step_key is None:
                    # If we don't have step info, put under 1 to preserve backward compatibility
                    step_key = 1

                if step_key not in params_by_step:
                    params_by_step[step_key] = { 'values': {}, 'files': {} }

                # Grab corresponding entries from the parallel state lists
                value = param_values[idx] if param_values and idx < len(param_values) else None
                contents = file_contents[idx] if file_contents and idx < len(file_contents) else None
                filename = file_names[idx] if file_names and idx < len(file_names) else None

                param_name = pid.get('param')
                if param_name:
                    params_by_step[step_key]['values'][param_name] = value
                    # If this input provided file contents, map it too
                    if contents:
                        params_by_step[step_key]['files'][param_name] = { 'contents': contents, 'filename': filename }
        
        # Add steps with their parameters
        for i, (module, wait) in enumerate(zip(modules, waits)):
            if module:  # Only add steps with selected modules
                # Get technique parameters to validate and collect only this technique's params
                technique = TechniqueRegistry.get_technique(module)()
                technique_params = technique.get_parameters()
                
                # Build params dict for this step by checking which params belong to this technique
                step_no = i + 1
                step_params = {}
                step_data = params_by_step.get(step_no, { 'values': {}, 'files': {} })
                for param_name in technique_params:
                    param_config = technique_params[param_name]

                    # File upload parameter handling
                    if param_config.get('input_field_type') == 'upload':
                        if param_name in step_data['files']:
                            step_params[param_name] = step_data['files'][param_name]['contents']
                        elif param_config.get('required', False):
                            raise ValueError(f"Required file parameter '{param_name}' not provided for module {module} (step {step_no})")
                    else:
                        if param_name in step_data['values']:
                            param_value = step_data['values'][param_name]
                            # Treat empty strings as missing values
                            if param_value == "":
                                if param_config.get('required', False):
                                    raise ValueError(f"Required parameter '{param_name}' not provided for module {module} (step {step_no})")
                                else:
                                    param_value = None
                            step_params[param_name] = param_value
                        elif param_config.get('required', False):
                            raise ValueError(f"Required parameter '{param_name}' not provided for module {module} (step {step_no})")
                
                new_step = PlaybookStep(
                    module=module,
                    params=step_params,
                    wait=int(wait) if wait else 0
                )
                new_playbook.add_step(new_step, i + 1)
        
        # get updated list of available playbooks
        playbooks = GetAllPlaybooks()
        playbook_items = []
        
        for pb_file in playbooks:
            try:
                pb_config = Playbook(pb_file)
                # Apply search filter if query exists
                playbook_items.append(create_playbook_item(pb_config))
            except Exception as e:
                print(f"Error loading playbook {pb_file}: {str(e)}")
        
        stats = get_playbook_stats()
        stats_text = (f"{stats['total_playbooks']} playbooks loaded • "f"Last sync: {stats['last_sync'].strftime('%I:%M %p') if stats['last_sync'] else 'never'}")

        return True, f"New Playbook Created: {name}", False, "", False, [], playbook_items, stats_text
    
    except Exception as e:
        # On error: keep form open with user's data intact (no_update for children)
        return False, "", True, str(e), no_update, no_update, no_update, no_update
    
'''Playbook editor callbacks'''
'''[Playbook Editor] Callback to open playbook editor and load playbook data'''
@callback(
    Output("playbook-editor-offcanvas", "is_open", allow_duplicate = True),
    Output("playbook-editor-offcanvas", "children", allow_duplicate=True),
    Output(component_id="selected-playbook-data-editor-memory-store", component_property="data", allow_duplicate= True),
    Input({'type': 'edit-playbook-button', 'index': ALL}, 'n_clicks'),
    prevent_initial_call=True
)
def open_and_load_playbook_editor(n_clicks):
    """Open editor offcanvas and load existing playbook data in a single callback"""
    if not n_clicks:
        raise PreventUpdate
    
    # Find which button was clicked
    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    # Extract playbook file name from context
    button_id = ctx.triggered[0]['prop_id'].rsplit('.',1)[0]
    selected_pb = eval(button_id)['index']
    
    # Find the selected playbook
    try:
        playbook = Playbook(selected_pb)

        # Generate step forms with existing data
        steps = []
        for step_no, step_data in playbook.data['PB_Sequence'].items():
            param_form = generate_attack_technique_config(
                                step_data.get('Module'),
                                mode="automator",
                                existing_values=step_data.get('Params', {}),
                                step_index=int(step_no),
                                id_type="editor"
                            )

            step_form = dbc.Card([
                dbc.CardHeader([
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.I(
                                    className="fas fa-layer-group me-2", 
                                    style={
                                        "color": "#dc3545", 
                                        "fontSize": "1rem"
                                    }
                                ),
                                html.Span(
                                    f"Step {step_no}", 
                                    className="halberd-brand",
                                    style={
                                        "fontSize": "1rem",
                                        "fontWeight": "700",
                                        "color": "#ffffff"
                                    }
                                )
                            ], className="d-flex align-items-center")
                        ], width=10),
                        dbc.Col([
                            dbc.Button(
                                html.I(className="fas fa-trash-alt"),
                                id={"type": "remove-step-editor-button", "index": step_no},
                                color="link",
                                className="text-danger p-0",
                                title="Remove step"
                            ) if int(step_no) > 1 else None
                        ], width=2, className="text-end")
                    ], className="align-items-center")
                ], style={
                    "background": "linear-gradient(135deg, rgba(220, 53, 69, 0.15) 0%, rgba(108, 117, 125, 0.15) 100%)",
                    "borderBottom": "2px solid rgba(220, 53, 69, 0.3)",
                    "borderRadius": "8px 8px 0 0"
                }),
                dbc.CardBody([
                    # Module selector
                    dbc.Row([
                        dbc.Col([
                            dbc.Label(
                                [
                                    html.I(className="fas fa-cube me-2", style={"color": "#6c757d"}),
                                    "Module *"
                                ],
                                className="halberd-text mb-2 d-block",
                                style={"fontWeight": "600"}
                            ),
                            dcc.Dropdown(
                                id={"type": "step-module-dropdown-editor", "index": step_no},
                                options=[
                                    {"label": technique().name, "value": tid}
                                    for tid, technique in TechniqueRegistry.list_techniques().items()
                                ],
                                value=step_data.get('Module'),
                                placeholder="Select technique module...",
                                className="halberd-dropdown",
                                style={
                                    "background": "rgba(33, 37, 41, 0.8)",
                                    "border": "2px solid rgba(108, 117, 125, 0.3)",
                                    "borderRadius": "8px"
                                }
                            )
                        ])
                    ], className="mb-4"),
                    
                    # Parameters container with header
                    html.Div([
                        html.Div([
                            html.I(className="fas fa-sliders-h me-2", style={"color": "#6c757d", "fontSize": "0.9rem"}),
                            html.Span("Parameters", style={"fontSize": "0.9rem", "fontWeight": "600"})
                        ], className="text-muted mb-3"),
                        html.Div(
                            # Create parameter inputs if module data available (use central helper)
                            param_form if step_data.get('Module') else [],
                            
                            id={"type": "step-params-container-editor", "index": step_no},
                            style={
                                "minHeight": "50px",
                                "padding": "10px",
                                "backgroundColor": "rgba(33, 37, 41, 0.4)",
                                "borderRadius": "8px",
                                "border": "1px solid rgba(108, 117, 125, 0.2)"
                            }
                        )
                    ], className="mb-4"),

                    # Wait time input
                    dbc.Row([
                        dbc.Col([
                            dbc.Label(
                                [
                                    html.I(className="fas fa-hourglass-end me-2", style={"color": "#6c757d"}),
                                    "Wait After Step (seconds)"
                                ],
                                className="halberd-text mb-2 d-block",
                                style={"fontWeight": "600"}
                            ),
                            dbc.Input(
                                type="number",
                                id={"type": "step-wait-input-editor", "index": step_no},
                                value=step_data.get('Wait', 0),
                                placeholder="0",
                                min=0,
                                className="halberd-input",
                                style={
                                    "background": "rgba(33, 37, 41, 0.8)",
                                    "border": "2px solid rgba(108, 117, 125, 0.3)",
                                    "borderRadius": "8px",
                                    "color": "#ffffff",
                                    "padding": "12px 16px"
                                }
                            )
                        ], width=12)
                    ], className="mb-0"),
                ], style={
                    "padding": "24px",
                    "backgroundColor": "rgba(33, 37, 41, 0.5)"
                })
            ], className="mb-3 halberd-depth-card", style={
                "border": "1px solid rgba(220, 53, 69, 0.2)",
                "borderRadius": "12px"
            })
            steps.append(step_form)
                
        # Return complete editor form with all data populated
        form_content = dbc.Form([
            dbc.Row([
                dbc.Col([
                    dbc.Label("Playbook Name *", html_for="pb-name-input-editor"),
                    dbc.Input(
                        type="text",
                        id="pb-name-input-editor",
                        placeholder="Enter playbook name",
                        value=playbook.name,
                        className="bg-halberd-dark halberd-input halberd-text"
                    )
                ])
            ], className="mb-3"),
            
            dbc.Row([
                dbc.Col([
                    dbc.Label("Description *", html_for="pb-desc-input-editor"),
                    dbc.Textarea(
                        id="pb-desc-input-editor",
                        placeholder="Enter playbook description",
                        value=playbook.description,
                        className="bg-halberd-dark halberd-input halberd-text"
                    )
                ])
            ], className="mb-3"),
            
            dbc.Row([
                dbc.Col([
                    dbc.Label("Author *", html_for="pb-author-input-editor"),
                    dbc.Input(
                        type="text",
                        id="pb-author-input-editor",
                        placeholder="Enter author name",
                        value=playbook.author,
                        className="bg-halberd-dark halberd-input halberd-text"
                    )
                ])
            ], className="mb-3"),
            
            dbc.Row([
                dbc.Col([
                    dbc.Label("References", html_for="pb-refs-input-editor"),
                    dbc.Input(
                        type="text",
                        id="pb-refs-input-editor",
                        placeholder="Enter references (optional)",
                        value=', '.join(playbook.references) if playbook.references else '',
                        className="bg-halberd-dark halberd-input halberd-text"
                    )
                ])
            ], className="mb-4"),

            # Steps section
            html.Div([
                html.H4("Playbook Steps", className="mb-3 halberd-brand-heading"),
                html.Div(steps, id="playbook-steps-editor-container"),
                
                # Add step button
                dbc.Button(
                    [html.I(className="bi bi-plus-lg me-2"), "Add Step"],
                    id="add-playbook-step-editor-button",
                    color="secondary",
                    className="mt-3 mb-4"
                ),
            ]),

            # Update playbook button
            dbc.Button(
                [html.I(className="bi bi-save me-2"), "Update Playbook"],
                id="update-playbook-editor-button",
                className="w-100 halberd-button"
            )
        ])
        
        # Return: is_open=True, form_content, selected_playbook_name
        return True, form_content, selected_pb
        
    except:
        raise PreventUpdate

'''[Playbook Editor] Callback to add a new step in existing playbook'''
@callback(
    Output("playbook-steps-editor-container", "children", allow_duplicate=True),
    Input("add-playbook-step-editor-button", "n_clicks"),
    State("playbook-steps-editor-container", "children"),
    prevent_initial_call=True
)
def add_playbook_step_editor(n_clicks, current_steps):
    """Add a new step form to the playbook editor"""
    if n_clicks:
        new_step_number = len(current_steps) + 1
        new_step = dbc.Card([
            dbc.CardBody([
                # Step header
                dbc.Row([
                    dbc.Col([
                        html.H5(f"Step {new_step_number}", className="mb-3 text-success")
                    ], width=10),
                    dbc.Col([
                        html.Button(
                            html.I(className="bi bi-trash"),
                            id={"type": "remove-step-editor-button", "index": new_step_number},
                            className="btn btn-link text-danger",
                            style={"float": "right"}
                        )
                    ], width=2)
                ]),
                
                # Module selector
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Module *"),
                        dcc.Dropdown(
                            id={"type": "step-module-dropdown-editor", "index": new_step_number},
                            options=[
                                {"label": technique().name, "value": tid}
                                for tid, technique in TechniqueRegistry.list_techniques().items()
                            ],
                            placeholder="Select module",
                            className="bg-halberd-dark halberd-dropdown halberd-text"
                        )
                    ])
                ], className="mb-3"),
                
                # Wait time input
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Wait (seconds)"),
                        dbc.Input(
                            type="number",
                            id={"type": "step-wait-input-editor", "index": new_step_number},
                            placeholder="0",
                            min=0,
                            value=0,
                            className="bg-halberd-dark halberd-input"
                        )
                    ])
                ], className="mb-3"),
                
                # Parameters container (initially empty)
                html.Div(
                    id={"type": "step-params-container-editor", "index": new_step_number}
                )
            ])
        ], className="mb-3 halberd-depth-card")
        
        return current_steps + [new_step]
    return current_steps

'''[Playbook Editor] Callback to update parameters on technique change from dropdown'''
@callback(
    Output({"type": "step-params-container-editor", "index": MATCH}, "children"),
    Input({"type": "step-module-dropdown-editor", "index": MATCH}, "value"),
    prevent_initial_call=True
)
def update_step_parameters_editor(module_id):
    """Update parameter fields when module selection changes"""
    if not module_id:
        return []
    # Determine which editor step triggered this MATCH callback so we can
    # include the step index in generated parameter IDs.
    ctx = callback_context
    if not ctx.triggered:
        return []

    triggered_id = json.loads(ctx.triggered[0]["prop_id"].rsplit('.', 1)[0])
    step_index = triggered_id.get("index")
    return generate_attack_technique_config(module_id, mode="automator", step_index=step_index, id_type="editor")

@callback(
    Output("app-notification", "is_open", allow_duplicate=True),
    Output("app-notification", "children", allow_duplicate=True),
    Output("app-error-display-modal", "is_open", allow_duplicate=True),
    Output("app-error-display-modal-body", "children", allow_duplicate=True),
    Output("playbook-editor-offcanvas", "is_open", allow_duplicate = True),
    Output("playbook-editor-offcanvas", "children", allow_duplicate=True),
    Input("update-playbook-editor-button", "n_clicks"),
    [
        State("pb-name-input-editor", "value"),
        State("pb-desc-input-editor", "value"),
        State("pb-author-input-editor", "value"),
        State("pb-refs-input-editor", "value"),
        State({"type": "step-module-dropdown-editor", "index": ALL}, "value"),
        State({"type": "step-wait-input-editor", "index": ALL}, "value"),
    State({"type": "attack-technique-config-editor", "step": ALL, "technique": ALL, "param": ALL}, "value"),
    State({"type": "attack-technique-config-editor", "step": ALL, "technique": ALL, "param": ALL}, "id"),
    State({"type": "attack-technique-config-editor", "step": ALL, "technique": ALL, "param": ALL}, "contents"),
    State({"type": "attack-technique-config-editor", "step": ALL, "technique": ALL, "param": ALL}, "filename"),
        State("selected-playbook-data-editor-memory-store", "data"),
    ],
    prevent_initial_call=True
)
def update_playbook_from_editor(n_clicks, name, desc, author, refs, modules, waits, param_values, param_ids, file_contents, file_names, selected_playbook):
    """Update existing playbook from editor data"""
    if not n_clicks:
        raise PreventUpdate

    try:
        # Find the selected playbook
        playbook = Playbook(selected_playbook)
        # Update playbook metadata
        playbook.data['PB_Name'] = name
        playbook.data['PB_Description'] = desc
        playbook.data['PB_Author'] = author
        playbook.data['PB_References'] = [ref.strip() for ref in refs.split(',')] if refs else []
        
        # Clear existing sequence
        playbook.data['PB_Sequence'] = {}
        
        # Build a nested parameter map keyed by step number so editor parameters
        # map correctly to their step. Each param_id should contain a 'step'
        # key (added when generating inputs). If missing, fall back to step 1.
        params_by_step = {}
        if param_ids:
            for idx, pid in enumerate(param_ids):
                step_key = None
                if isinstance(pid, dict):
                    step_key = pid.get('step')
                try:
                    step_key = int(step_key) if step_key is not None else None
                except Exception:
                    pass

                if step_key is None:
                    step_key = 1

                if step_key not in params_by_step:
                    params_by_step[step_key] = { 'values': {}, 'files': {} }

                value = param_values[idx] if param_values and idx < len(param_values) else None
                contents = file_contents[idx] if file_contents and idx < len(file_contents) else None
                filename = file_names[idx] if file_names and idx < len(file_names) else None

                param_name = pid.get('param') if isinstance(pid, dict) else pid
                if param_name:
                    params_by_step[step_key]['values'][param_name] = value
                    if contents:
                        params_by_step[step_key]['files'][param_name] = { 'contents': contents, 'filename': filename }

        # Now validate and assemble per-step params based on technique parameter definitions
        step_params = {}
        for i, module in enumerate(modules):
            if module:
                technique = TechniqueRegistry.get_technique(module)()
                technique_params = technique.get_parameters()
                step_no = i + 1
                step_params[i] = {}
                step_data = params_by_step.get(step_no, { 'values': {}, 'files': {} })

                for param_name in technique_params:
                    param_config = technique_params[param_name]

                    # File upload parameter handling
                    if param_config.get('input_field_type') == 'upload':
                        if param_name in step_data['files']:
                            step_params[i][param_name] = step_data['files'][param_name]['contents']
                        elif param_config.get('required', False):
                            raise ValueError(f"Required file parameter '{param_name}' not provided for module {module} (step {step_no})")
                    else:
                        if param_name in step_data['values']:
                            param_value = step_data['values'][param_name]
                            # Treat empty strings as missing values
                            if param_value == "":
                                if param_config.get('required', False):
                                    raise ValueError(f"Required parameter '{param_name}' not provided for module {module} (step {step_no})")
                                else:
                                    param_value = None
                            step_params[i][param_name] = param_value
                        elif param_config.get('required', False):
                            raise ValueError(f"Required parameter '{param_name}' not provided for module {module} (step {step_no})")
        
        # Add updated steps
        for i, (module, wait) in enumerate(zip(modules, waits)):
            if module:
                playbook.data['PB_Sequence'][i + 1] = {
                    'Module': module,
                    'Params': step_params.get(i, {}),
                    'Wait': int(wait) if wait else 0
                }
        
        # Save updated playbook
        playbook.save()
        return True, f"Playbook Updated: {name}", False, "", False, []  # Clear children on success
        
    except Exception as e:
        print(f"ERROR in update_playbook_from_editor: {str(e)}")
        import traceback
        traceback.print_exc()
        # On error: keep form open with user's data intact (no_update for children)
        return False, "", True, str(e), no_update, no_update

'''[Playbook Editor] Callback to remove step from playbook and update the playbook steps'''
@callback(
    Output("playbook-steps-editor-container", "children", allow_duplicate=True),
    Input({"type": "remove-step-editor-button", "index": ALL}, "n_clicks"),
    State("playbook-steps-editor-container", "children"),
    prevent_initial_call=True
)
def remove_playbook_step_editor(n_clicks, current_steps):
    """Remove a step from the playbook editor and renumber remaining steps"""
    if not any(n_clicks) or not current_steps:
        raise PreventUpdate
    
    # Find which button was clicked
    ctx = dash.callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    try:
        button_id = json.loads(ctx.triggered[0]["prop_id"].split(".")[0])
        step_to_remove = button_id["index"]
        
        # Create new list without the removed step
        remaining_steps = []
        new_step_number = 1
        
        for step in current_steps:
            # Extract current step number from the card
            current_step_header = step["props"]["children"]["props"]["children"][0]["props"]["children"][0]["props"]["children"]["children"]
            current_step_num = int(current_step_header.split()[1])
            
            if current_step_num != step_to_remove:
                # Update step number in header
                step["props"]["children"]["props"]["children"][0]["props"]["children"][0]["props"]["children"]["children"] = f"Step {new_step_number}"
                
                # Update all component IDs that contain step number
                for component in [
                    {"type": "remove-step-editor-button", "location": [0, "props", "children", 1, "props", "children", "props", "id"]},
                    {"type": "step-module-dropdown-editor", "location": [1, "props", "children", 0, "props", "children", 1, "props", "id"]},
                    {"type": "step-wait-input-editor", "location": [2, "props", "children", 0, "props", "children", 1, "props", "id"]},
                    {"type": "step-params-container-editor", "location": [3, "props", "id"]}
                ]:
                    try:
                        # Navigate to the component's location
                        current = step["props"]["children"]["props"]["children"]
                        for loc in component["location"][:-1]:
                            current = current[loc]
                        # Update the ID
                        current[component["location"][-1]]["index"] = new_step_number
                    except (KeyError, IndexError, TypeError):
                        continue
                
                remaining_steps.append(step)
                new_step_number += 1
        
        return remaining_steps
    except Exception as e:
        print(f"Error in remove_playbook_step_editor: {str(e)}")
        raise PreventUpdate

'''[Playbook Progress Tracker] Callback to update the execution progress display'''
@callback(
    Output("playbook-execution-progress", "children"),
    Output("execution-interval", "disabled"),
    Input("execution-interval", "n_intervals"),
    State("selected-playbook-data", "data"),
    prevent_initial_call=True
)
def update_execution_progress(n_intervals, playbook_data):
    """Update the execution progress display"""
    if not playbook_data:
        raise PreventUpdate
        
    try:
        # Get playbook config
        playbook = Playbook(playbook_data)
        total_steps = len(playbook.data['PB_Sequence'])
        
        # Get latest execution folder
        execution_folders = [
            d for d in os.listdir(AUTOMATOR_OUTPUT_DIR)
            if d.startswith(f"{playbook.name}_")
        ]
        
        if not execution_folders:
            raise PreventUpdate
            
        latest_folder = max(execution_folders)
        execution_folder = os.path.join(AUTOMATOR_OUTPUT_DIR, latest_folder)
        
        # Get execution results
        results = parse_execution_report(execution_folder)
        active_step = len(results)
        
        # Create status cards for each step
        step_cards = []
        for step_no, step_data in playbook.data['PB_Sequence'].items():
            step_index = int(step_no) - 1
            
            # Determine step status
            status = None
            message = None
            is_active = False
            
            if step_index < len(results):
                status = results[step_index].get('status')
            elif step_index == len(results):
                is_active = True
                
            step_cards.append(
                create_step_progress_card(
                    step_number=step_no,
                    module_name=step_data['Module'],
                    status=status,
                    is_active=is_active,
                    message=message
                )
            )
        
        # Create progress tracker component
        progress_tracker = dbc.Card([
            dbc.CardHeader([
                dbc.Row([
                    dbc.Col(
                        html.H5("Execution Progress", className="mb-0"),
                        width=8
                    ),
                    dbc.Col(
                        html.Small(
                            f"Step {active_step} of {total_steps}",
                            className="text-muted"
                        ),
                        width=4,
                        className="text-end"
                    )
                ])
            ]),
            dbc.CardBody(step_cards)
        ], className="bg-halberd-dark text-light mb-4")
        
        # Check if execution is complete
        is_complete = active_step == total_steps
        
        return progress_tracker, is_complete
        
    except Exception as e:
        print(f"Error updating progress: {str(e)}")
        raise PreventUpdate

'''[Playbook Progress Tracker] Callback to handle the off-canvas visibility and button display'''
@callback(
    Output("execution-progress-offcanvas", "is_open", allow_duplicate=True),
    Output("view-progress-button-container", "style", allow_duplicate=True),
    Output("execution-interval", "disabled", allow_duplicate=True),
    [
        Input({'type': 'execute-playbook-button', 'index': ALL}, 'n_clicks'),
        Input("view-progress-button", "n_clicks")
    ],
    [
        State("execution-progress-offcanvas", "is_open")
    ],
    prevent_initial_call=True
)
def manage_progress_display(execute_clicks, view_clicks, is_open):
    """Manage progress display visibility"""
    ctx = dash.callback_context
    if not ctx.triggered:
        raise PreventUpdate
        
    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    # Handle execute button clicks
    if "execute-playbook-button" in trigger_id:
        if any(click for click in execute_clicks if click):
            # Show button and open offcanvas
            return True, {"display": "block"}, False
            
    # Handle view progress button clicks
    elif trigger_id == "view-progress-button" and view_clicks:
        return not is_open, {"display": "block"}, False
        
    raise PreventUpdate