'''
Page Navigation URL : app/automator
Page Description : Allows management / execution of playbooks and scheduling.
'''

from dash import dcc, html
import dash
import dash_bootstrap_components as dbc
import dash_daq as daq
from datetime import date
from core.Functions import GetAllPlaybooks, Playbook

def PlaybooksDropdownListGen():
    return [
        {
            "label": html.Div([Playbook(pb).name], style={'font-size': 16}),
            "value": Playbook(pb).name,
        }
        for pb in GetAllPlaybooks()
    ]

page_layout = dbc.Container([
    html.H2("Attack Automator", className="text-success mb-3"),
    
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader(html.H3("Playbook Library", className="mb-2"), className="bg-dark text-light"),
                dbc.CardBody([
                    dcc.Dropdown(
                        id='automator-pb-selector-dropdown',
                        options=PlaybooksDropdownListGen(),
                        placeholder="Select Playbook",
                        value=None,
                        className="mb-3",
                        style={'color': 'black'}
                    ),
                    dbc.Button("Details", id="pb-view-details-button", n_clicks=0, color="info", className="me-2"),
                    dbc.Button("Execute", id="execute-sequence-button", n_clicks=0, color="danger", className="me-2"),
                    dbc.Button("Schedule", id="toggle-scheduler-modal-open-button", n_clicks=0, color="success", className="me-2"),
                    dbc.Button("Export", id="toggle-export-playbook-modal-open-button", n_clicks=0, color="secondary", className="me-2"),
                    dbc.Button("Delete", id="delete-pb-button", n_clicks=0, color="primary", className="me-2"),
                ], className="bg-dark")
            ], className="mb-4"),
        ], md=10),
        
        dbc.Col([
            dbc.Card([
                dbc.CardHeader(html.H3("Add Playbook", className="mb-2"), className="bg-dark text-light"),
                dbc.CardBody([
                    dbc.Button("Create New", id="pb-creator-modal-open-button", n_clicks=0, color="success", className="w-100 mb-2"),
                    dcc.Upload(
                        id="upload-playbook",
                        children=dbc.Button("Import", id="import-pb-button", n_clicks=0, color="info", className="w-100 mb-2"),
                    ),
                ], className="bg-dark")
            ], className="mb-4"),
        ], md=2)
    ]),
    dbc.Card([
        dbc.CardHeader(html.H4("Playbook Information", className="mb-2"), className="bg-dark text-light"),
        dbc.CardBody([
            # Playbook path visualization
            dbc.Card([
                dbc.CardBody([
                    html.Div(html.H4("Select Playbook"), id="attack-automator-path-display-div", style={"height": "20vh", "overflowY": "auto"}, className="text-light")
                ], className="bg-dark")
            ], className="border-secondary"),
            html.Br(),
            html.Div(id="playbook-node-data-div", style={"height": "40vh", "overflowY": "auto"}, className="text-light")
        ], className="bg-dark")
    ], className="mb-4"),
    
    # Modal to configure scheduled playbook
    dbc.Modal([
        dbc.ModalHeader("Schedule Playbook", className="bg-dark text-light"),
        dbc.ModalBody([
            dbc.Row([
                dbc.Col([
                    dbc.Label("Execution Time", className="text-light"),
                    dbc.Input(id='set-time-input', type="time", required=True, className="bg-dark text-light")
                ], className="mb-3"),
            ]),
            dbc.Row([
                dbc.Col([
                    dbc.Label("Date Range", className="text-light"),
                    dcc.DatePickerRange(
                        id='automator-date-range-picker',
                        min_date_allowed=date.today(),
                        max_date_allowed=date(9999, 12, 31),
                        initial_visible_month=date(2024, 8, 5),
                    )
                ], className="mb-3"),
            ]),
            dbc.Row([
                dbc.Col([
                    dbc.Label("Repeat", className="text-light"),
                    daq.BooleanSwitch(id='schedule-repeat-boolean', on=False, color="#00FF00")
                ], className="mb-3"),
            ]),
            dbc.Row([
                dbc.Col([
                    dbc.Label("Repeat Frequency", className="text-light"),
                    dcc.Dropdown(id='repeat-options-dropdown', options=["Daily", "Weekly", "Monthly"], className="bg-dark text-light")
                ], className="mb-3"),
            ]),
            dbc.Row([
                dbc.Col([
                    dbc.Label("Schedule Name (Optional)", className="text-light"),
                    dbc.Input(id='schedule-name-input', placeholder="my_schedule", className="bg-dark text-light")
                ], className="mb-3"),
            ]),
        ], className="bg-dark"),
        dbc.ModalFooter([
            dbc.Button("Schedule", id="schedule-sequence-button", n_clicks=0, color="danger"),
            dbc.Button("Close", id="toggle-scheduler-modal-close-button", n_clicks=0, color="secondary")
        ], className="bg-dark")
    ], id="scheduler-modal", className="text-light"),
    
    # Modal to create a new plabook
    dbc.Modal([
        dbc.ModalHeader("Create New Playbook", className="bg-dark text-light"),
        dbc.ModalBody([
            dbc.Row([
                dbc.Col([
                    dbc.Label("Playbook Name", className="text-light"),
                    dbc.Input(id='pb-name-input', required=True, placeholder="Enter playbook name", className="bg-dark text-light")
                ], className="mb-3"),
            ]),
            dbc.Row([
                dbc.Col([
                    dbc.Label("Description", className="text-light"),
                    dbc.Textarea(id='pb-desc-input', placeholder="Enter playbook description", className="bg-dark text-light")
                ], className="mb-3"),
            ]),
            dbc.Row([
                dbc.Col([
                    dbc.Label("Author", className="text-light"),
                    dbc.Input(id='pb-author-input', placeholder="Enter author name", className="bg-dark text-light")
                ], className="mb-3"),
            ]),
            dbc.Row([
                dbc.Col([
                    dbc.Label("References", className="text-light"),
                    dbc.Input(id='pb-refs-input', placeholder="Enter references", className="bg-dark text-light")
                ], className="mb-3"),
            ]),
        ], className="bg-dark"),
        dbc.ModalFooter([
            dbc.Button("Create", id="create-playbook-button", n_clicks=0, color="danger"),
            dbc.Button("Close", id="pb-creator-modal-close-button", n_clicks=0, color="secondary")
        ], className="bg-dark")
    ], id="playbook-creator-modal", className="text-light"),

    # Modal to export playbook
    dbc.Modal([
        dbc.ModalHeader("Export Playbook", className="bg-dark text-light"),
        dbc.ModalBody([
            dbc.Row([
                dbc.Col([
                    dbc.Label("Mask Param Values", className="text-light"),
                    daq.BooleanSwitch(id="export-playbook-mask-param-boolean", on=True, color="#00FF00")
                ], className="mb-3"),
            ]),
            dbc.Row([
                dbc.Col([
                    dbc.Label("Export File Name (Optional)", className="text-light"),
                    dbc.Input(id="export-playbook-filename-text-input", placeholder="my_playbook_007", className="bg-dark text-light")
                ], className="mb-3"),
            ]),
        ], className="bg-dark"),
        dbc.ModalFooter([
            dbc.Button("Export", id="export-playbook-button", n_clicks=0, color="danger"),
            dbc.Button("Close", id="toggle-export-playbook-modal-close-button", n_clicks=0, color="secondary")
        ], className="bg-dark")
    ], id="export-playbook-modal", className="text-light"),

    # Display playbook info
    dbc.Modal(
        [
            dbc.ModalHeader(dbc.ModalTitle("Playbook Details")),
            dbc.ModalBody(id = "automator-playbook-info-display-modal-body"),
            dbc.ModalFooter(
                dbc.Button("Close", id="close-automator-playbook-info-display-modal", className="ml-auto")
            ),
        ],
        id="automator-playbook-info-display-modal",
        size="lg",
        scrollable=True,
    ),
    
    # Element to trigger download/export of playbooks
    dcc.Download(id="download-pb-config-file")
], fluid=True, className="bg-dark", style={"min-height": "93vh"})