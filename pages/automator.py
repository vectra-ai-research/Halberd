'''
Page Navigation URL : app/automator
Page Description : Manage (add/edit/schedule/import/export) and execute playbooks.
'''

from dash import html, dcc
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify
import dash_daq as daq
from datetime import date
from attack_techniques.technique_registry import TechniqueRegistry

def create_playbook_manager_layout():
    """Creates the playbook management interface layout"""
    return html.Div([
        dbc.Row([
            # Left Panel - Playbook List
            dbc.Col([
                # Primary management buttons       
                html.Div([
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
                        color="success",
                        className="me-2 halberd-button-secondary"
                    ),
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
                            className="me-2 halberd-button-secondary"
                        ),
                    ),
                    html.Div(
                        # View progress button
                        dbc.Button([
                            DashIconify(
                                icon="mdi:progress-clock",
                                width=20,
                                className="me-2"
                            ),
                            "View Progress"
                        ],
                        id="view-progress-button",
                        n_clicks=0,
                        className="me-2 halberd-button-secondary"
                        ),
                        id="view-progress-button-container"
                    )
                ], className="d-flex justify-content-between align-items-center mb-3"),
                # Search bar
                html.Div([
                    dbc.InputGroup([
                        dbc.InputGroupText(
                            DashIconify(icon="mdi:magnify", className="text-muted"),
                            className="bg-halberd-dark border-secondary"
                        ),
                        dbc.Input(
                            id="playbook-search",
                            placeholder="Search playbooks...",
                            type="text",
                            className="bg-halberd-dark text-light border-secondary",
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
                        generate_step_form(1)
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

def generate_step_form(step_number):
    """Generate form elements for a single playbook step"""
    return dbc.Card([
        dbc.CardBody([
            dbc.Row([
                dbc.Col([
                    html.H5(f"Step {step_number}", className="mb-3")
                ], width=10),
                dbc.Col([
                    html.Button(
                        html.I(className="bi bi-trash"),
                        id={"type": "remove-step-button", "index": step_number},
                        className="btn btn-link text-danger",
                        style={"float": "right"}
                    ) if step_number > 1 else None
                ], width=2)
            ]),
            
            dbc.Row([
                dbc.Col([
                    dbc.Label("Module *"),
                    dcc.Dropdown(
                        id={"type": "step-module-dropdown", "index": step_number},
                        options=[
                            {"label": technique().name, "value": tid}
                            for tid, technique in TechniqueRegistry.list_techniques().items()
                        ],
                        placeholder="Select module",
                        className="bg-halberd-dark halberd-text halberd-dropdown"
                    )
                ])
            ], className="mb-3"),
            
            # Dynamic parameters section
            html.Div(id={"type": "step-params-container", "index": step_number}),

            dbc.Row([
                dbc.Col([
                    dbc.Label("Wait (seconds)"),
                    dbc.Input(
                        type="number",
                        id={"type": "step-wait-input", "index": step_number},
                        placeholder="0",
                        min=0,
                        className="bg-halberd-dark halberd-input halberd-text"
                    )
                ])
            ], className="mb-3"),
        ])
    ], className="mb-3 halberd-depth-card")

def generate_playbook_editor_offcanvas():
    return dbc.Offcanvas(
        [            
            # Playbook metadata form
            dbc.Form([
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
        ],
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

def playbook_editor_create_parameter_inputs(module_id, existing_params=None):
    """Helper function to create parameter input elements"""
    if not module_id:
        return []
    
    # Initialize existing_params to empty dict if None
    existing_params = existing_params or {}
    
    technique = TechniqueRegistry.get_technique(module_id)()
    params = technique.get_parameters()
    
    if not params:
        return html.P("No config required", className="halberd-text")
    
    param_inputs = []
    for param_name, param_config in params.items():
        required = param_config.get("required", False)
        label_text = f"{param_config['name']} {'*' if required else ''}"
        
        input_type = param_config.get("input_field_type", "text")
        
        # Create input with existing value if available
        if input_type == "bool":
            input_elem = daq.BooleanSwitch(
                id={"type": "param-input-editor", "param": param_name},
                on=existing_params.get(param_name, param_config.get("default", False))
            )
        else:
            input_elem = dbc.Input(
                type=input_type,
                id={"type": "param-input-editor", "param": param_name},
                value=existing_params.get(param_name, param_config.get("default", "")),
                placeholder=param_config.get("default", ""),
                className="bg-halberd-dark halberd-text halberd-input"
            )
        
        param_inputs.append(
            dbc.Row([
                dbc.Col([
                    dbc.Label(label_text, className="halberd-text"),
                    input_elem
                ])
            ], className="mb-3")
        )
    
    return param_inputs

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