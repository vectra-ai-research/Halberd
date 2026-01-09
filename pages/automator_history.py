'''
Page Navigation url : app/automator-history
Page Description : Page to view outputs from all playbook executions.
'''

import os
from dash import html, dcc, register_page, callback, ALL, callback_context, no_update
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify

from core.Functions import generate_automator_execution_table, parse_execution_report, ParseTechniqueResponse
from core.Constants import AUTOMATOR_OUTPUT_DIR
from core.output_manager.output_manager import OutputManager

# Register page to app
register_page(__name__, path='/automator-history', name='Automator History')

def generate_execution_steps_view(folder_name, playbook_name, execution_time):
    """Helper function to generate the execution steps view.
    
    Args:
        folder_name: Name of the execution folder
        playbook_name: Name of the playbook
        execution_time: Execution timestamp
        
    Returns:
        html.Div containing the execution steps view
    """
    # Build the folder path
    folder_path = os.path.join(AUTOMATOR_OUTPUT_DIR, folder_name)
    
    # Parse execution report for step details
    step_results = parse_execution_report(folder_path)
    
    if not step_results:
        return html.Div([
            html.P("No execution details found for this playbook.", className="text-muted")
        ])
    
    # Create step result cards
    step_cards = []
    for idx, step in enumerate(step_results, 1):
        module_name = step.get('module', 'Unknown')
        status = step.get('status', 'unknown')
        timestamp = step.get('timestamp', '')
        event_id = step.get('event_id', '')
        
        # Determine status color
        if status == 'success':
            status_color = 'success'
            status_icon = 'mdi:check-circle'
        elif status == 'failed':
            status_color = 'danger'
            status_icon = 'mdi:close-circle'
        else:
            status_color = 'secondary'
            status_icon = 'mdi:help-circle'
        
        step_cards.append(
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.Span(f"Step {idx}: ", className="fw-bold"),
                        html.Span(module_name),
                    ], className="d-flex align-items-center"),
                    dbc.Badge(
                        [
                            DashIconify(icon=status_icon, width=14, className="me-1"),
                            status.upper()
                        ],
                        color=status_color,
                        className="ms-auto"
                    )
                ], className="d-flex justify-content-between align-items-center"),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.Small("Timestamp:", className="text-muted"),
                            html.P(timestamp, className="mb-0")
                        ], md=6),
                        dbc.Col([
                            html.Small("Event ID:", className="text-muted"),
                            html.P(event_id[:8] + "..." if event_id else "N/A", className="mb-0", title=event_id)
                        ], md=6),
                    ]),
                    # View output button
                    dbc.Button(
                        [
                            DashIconify(icon="mdi:file-document-outline", width=16, className="me-1"),
                            "View Output"
                        ],
                        id={"type": "view-step-output-btn", "index": idx, "folder": folder_name, "module": module_name},
                        size="sm",
                        color="secondary",
                        outline=True,
                        className="mt-2"
                    )
                ])
            ], className="mb-2 halberd-depth-card")
        )
    
    # Create execution summary header
    summary_header = html.Div([
        html.H4([
            DashIconify(icon="mdi:playlist-check", width=24, className="me-2"),
            playbook_name
        ], className="mb-2"),
        html.P([
            html.Small("Executed: ", className="text-muted"),
            html.Span(execution_time)
        ], className="mb-3"),
        html.Hr()
    ])
    
    return html.Div([
        summary_header,
        html.H5("Execution Steps", className="mb-3"),
        html.Div(step_cards)
    ])

def generate_automator_history_page():
    return html.Div([
        html.H2(
            [
                "Automator History ",
                html.A(
                    DashIconify(icon="mdi:help-circle-outline", width=18, height=18), 
                    href="https://github.com/vectra-ai-research/Halberd/wiki/UI-&-Navigation#automator", 
                    target="_blank"
                )
            ],
            className="halberd-brand mb-3"
        ),

        dbc.Col([
            # Row 1 : Display execution history table
            dbc.Row(
                [
                    html.Div(
                        generate_automator_execution_table(), 
                        id="automator-execution-trace-div", 
                        style={
                            "height": "35vh", 
                            "overflowY": "auto", 
                            "padding-right": "10px", 
                            "padding-left": "10px", 
                            "padding-top": "10px", 
                            "padding-bottom": "5px"
                        }
                    )
                ],
                className="bg-halberd-dark",
            ),
            # Row 2: Display selected execution details
            dbc.Row(
                [
                    dcc.Loading(
                        id="automator-output-viewer-loading",
                        type="default",
                        children=html.Div(
                            # Default message when no execution is selected
                            html.Div([
                                dbc.Col([
                                    dbc.Row(
                                        DashIconify(
                                            icon="mdi:information-outline",
                                            width=48,
                                            height=48,
                                            className="text-muted mb-3 me-3"
                                        )
                                    ),
                                    dbc.Row(
                                        html.P("Select Execution From Table to View Details")
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
                            id="automator-output-viewer-display-div", 
                            style={
                                "height": "54vh", 
                                "overflowY": "auto", 
                                "border": "1px solid #ccc", 
                                "padding-right": "10px", 
                                "padding-left": "10px", 
                                "padding-top": "10px",
                                "padding-bottom": "10px"
                            },
                            className="halberd-text"
                        )
                    )
                ],
                className="bg-halberd-dark"
            )
        ])
    ], 
    className="bg-halberd-dark", 
    style={
        'position': 'fixed',
        'top': 92,
        'left': 0,
        'right': 0,
        'bottom': 0,
        'overflow': 'auto',
        "padding-right": "20px", 
        "padding-left": "20px",
    }
    )

# Create automator history layout
layout = generate_automator_history_page

# Callbacks
'''Callback to display execution details when a row is selected'''
@callback(
    Output(component_id="automator-output-viewer-display-div", component_property="children", allow_duplicate=True),
    Input(component_id="automator-execution-table", component_property="selected_rows"),
    Input(component_id="automator-execution-table", component_property="data"),
    prevent_initial_call=True
)
def display_execution_details_callback(selected_rows, data):
    if not selected_rows:
        return 'No execution selected'
    
    # Get the selected row's data
    selected_data = data[selected_rows[0]]
    folder_name = selected_data['Folder']
    playbook_name = selected_data['Playbook']
    execution_time = selected_data['Execution Time']
    
    return generate_execution_steps_view(folder_name, playbook_name, execution_time)

'''Callback to display step output when view output button is clicked'''
@callback(
    Output(component_id="automator-output-viewer-display-div", component_property="children", allow_duplicate=True),
    Input({"type": "view-step-output-btn", "index": ALL, "folder": ALL, "module": ALL}, "n_clicks"),
    prevent_initial_call=True
)
def display_step_output_callback(n_clicks):
    if not callback_context.triggered:
        return no_update
    
    # Get the triggered button id
    triggered_id = callback_context.triggered[0]['prop_id']
    
    # Check if any button was actually clicked
    if all(n is None for n in n_clicks):
        return no_update
    
    # Parse the button id to get folder and module
    import json
    button_id = json.loads(triggered_id.split('.')[0])
    folder_name = button_id['folder']
    module_name = button_id['module']
    
    # Build path to the result file
    result_file_path = os.path.join(AUTOMATOR_OUTPUT_DIR, folder_name, f"Result_{module_name}.txt")
    
    if not os.path.exists(result_file_path):
        return html.Div([
            html.P(f"Output file not found for module: {module_name}", className="text-muted")
        ])
    
    try:
        with open(result_file_path, 'r') as f:
            output_content = f.read()
    except Exception as e:
        return html.Div([
            html.P(f"Error reading output file: {str(e)}", className="text-danger")
        ])
    
    # Create back button and output display
    return html.Div([
        html.Div([
            dbc.Button(
                [
                    DashIconify(icon="mdi:arrow-left", width=16, className="me-1"),
                    "Back to Steps"
                ],
                id="back-to-steps-btn",
                size="sm",
                color="secondary",
                outline=True,
                className="mb-3"
            )
        ]),
        html.H5([
            DashIconify(icon="mdi:file-document", width=20, className="me-2"),
            f"Output: {module_name}"
        ], className="mb-3"),
        html.Hr(),
        html.Pre(
            output_content,
            style={
                'backgroundColor': '#1a1a1a',
                'color': '#e0e0e0',
                'padding': '15px',
                'borderRadius': '5px',
                'whiteSpace': 'pre-wrap',
                'wordWrap': 'break-word',
                'maxHeight': '40vh',
                'overflowY': 'auto'
            }
        )
    ])

'''Callback to navigate back to steps view from output view'''
@callback(
    Output(component_id="automator-output-viewer-display-div", component_property="children", allow_duplicate=True),
    Input(component_id="back-to-steps-btn", component_property="n_clicks"),
    State(component_id="automator-execution-table", component_property="selected_rows"),
    State(component_id="automator-execution-table", component_property="data"),
    prevent_initial_call=True
)
def back_to_steps_callback(n_clicks, selected_rows, data):
    if not n_clicks:
        return no_update
    
    if not selected_rows:
        return 'No execution selected'
    
    # Get the selected row's data
    selected_data = data[selected_rows[0]]
    folder_name = selected_data['Folder']
    playbook_name = selected_data['Playbook']
    execution_time = selected_data['Execution Time']
    
    return generate_execution_steps_view(folder_name, playbook_name, execution_time)

