'''
Page Navigation URL : app/automator

Page Description : Allows attack automation.
'''

from dash import dcc, html
import dash
import dash_bootstrap_components as dbc
import dash_daq as daq
from datetime import date
import dash_bootstrap_components as dbc
from core.Automator import GetAllPlaybooks, Playbook

# create the dropdown element
def PlaybooksDropdownListGen():
    playbook_dropdown_option = []    
    for pb in GetAllPlaybooks():
        
        playbook_dropdown_option.append(
            {
                "label": html.Div([Playbook(pb).name], style={'font-size': 20}, className="text-dark"),
                "value": Playbook(pb).name,
            }
        )
    return playbook_dropdown_option

page_layout = html.Div([
    html.H3("Attack Automator", style ={"textAlign": "center", "padding": "5px"}),
    html.Br(),
    html.H4("Attack Playbook", style ={ "padding": "5px"}),
    
    # playbook selector dropdown
    dcc.Dropdown(options = PlaybooksDropdownListGen(), value = None, id='automator-pb-selector-dropdown', placeholder="Select Playbook"),
    html.Br(),

    # div to display node information
    html.Div(id = "playbook-node-data-div", style={"height":"15vh", "overflowY": "auto", "border":"1px solid #ccc", "padding-right": "10px", "padding-left": "10px", "padding-top": "10px", "padding-bottom": "10px"}),
    html.Br(),

    # attack path display div 
    html.Div(id= "attack-automator-path-display-div",style={"height":"40vh", "overflowY": "auto", "border":"1px solid #ccc", "padding-right": "10px", "padding-left": "10px", "padding-top": "10px", "padding-bottom": "10px"}),
    html.Br(),

    
    
    html.Div([
        # execute playbook now button
        dbc.Button("Execute Now", id="execute-sequence-button", n_clicks=0, color="danger", style={'float': 'centre', 'margin-left': '10px'}),
        html.Br(),
        html.Br(),

        # setup automation button
        dbc.Button("Schedule Playbook", id="toggle-scheduler-modal-open-button", n_clicks=0, color="danger", style={'float': 'centre', 'margin-left': '10px'}),
        html.Br(),
        html.Br(),

        # import playbook button
        dcc.Upload(id = "upload-playbook", children= 
                       dbc.Button("Import Playbook", id="import-pb-button", n_clicks=0, color="danger", style={'float': 'centre', 'margin-left': '10px'}),
                ),
        html.Br(),
        html.Br(),

        # export playbook button
        dbc.Button("Export Playbook", id="export-pb-button", n_clicks=0, color="danger", style={'float': 'centre', 'margin-left': '10px'}),
        dcc.Download(id = "download-pb-config-file"),
        html.Br(),
        html.Br(),

        # create playbook button
        dbc.Button("Create New Playbook", id="pb-creator-modal-open-button", n_clicks=0, color="danger", style={'float': 'centre', 'margin-left': '10px'}),
    ], style={'display': 'flex', 'justify-content': 'center', 'gap': '10px'}),
    html.Br(),
    html.Br(),

    # view playbook schedules link
    html.A("View Playbook Schedules", href = dash.get_relative_path("/schedules"), target = "_blank"),

    # modal for scheduling playbook wizard
    dbc.Modal(
        [
            dbc.ModalHeader("Schedule Playbook"),
            dbc.ModalBody(
                html.Div(
                    [
                        html.H6("Attack Playbook ID", style ={ "padding": "5px"}),
                        dcc.Dropdown(options = PlaybooksDropdownListGen(), value = None, id='att-seq-selector-2-dropdown'),
                        html.Br(),
                        html.H6("Time"),
                        dcc.Input(id ='set-time-input', debounce=True, placeholder="00:00", required = True),
                        html.Br(),
                        html.Br(),
                        html.H6("Start / End Date"),
                        dcc.DatePickerRange(
                            id='automator-date-range-picker',
                            min_date_allowed=date.today(),
                            max_date_allowed=date(9999,12,31),
                            initial_visible_month=date(2024, 8, 5),
                        ),
                        html.Br(),
                        html.Br(),
                        daq.BooleanSwitch(id ='schedule-repeat-boolean', on=False, label="REPEAT"),
                        html.Br(),
                        html.H6("Repeat Frequency"),
                        dcc.Dropdown(options = ["Daily", "Weekly", "Monthly"], value = None, id='repeat-options-dropdown'),
                        html.Br(),
                        html.H6("Schedule Name (Optional)"),
                        dbc.Input(id ='schedule-name-input', debounce=True, placeholder="my_schedule"),
                    ]
                ),
            ),
            dbc.ModalFooter([
                dbc.Button(
                    "Schedule", id="schedule-sequence-button", n_clicks=0, color="danger", style={'float': 'centre', 'margin-left': '10px'}
                ),
                dbc.Button(
                    "Close", id="toggle-scheduler-modal-close-button", n_clicks=0, color="danger", style={'float': 'centre', 'margin-left': '10px'}
                ),
            ]
            ),
        ],
        id="scheduler-modal",
        is_open=False,
    ),

    # modal for creating new playbook wizard
    dbc.Modal(
        [
            dbc.ModalHeader("Create New Playbook"),
            dbc.ModalBody(
                html.Div(
                    [
                        html.H6("Playbook Name", style ={ "padding": "5px"}),
                        dbc.Input(id ='pb-name-input', debounce=True, placeholder="Road Not Taken", required = True, class_name="text-dark"),
                        html.Br(),
                        html.H6("Description"),
                        dbc.Textarea(id ='pb-desc-input', debounce=True, placeholder="Two roads diverged in a yellow wood, And sorry I could not travel both And be one traveler, long I stood And looked down one as far as I could To where it bent in the undergrowth;", class_name="text-dark"),
                        html.Br(),
                        html.H6("Author", style ={ "padding": "5px"}),
                        dbc.Input(id ='pb-author-input', debounce=True, placeholder="Robert Frost", class_name="text-dark"),
                        html.Br(),
                        html.H6("References", style ={ "padding": "5px"}),
                        dbc.Input(id ='pb-refs-input', debounce=True, placeholder="https://www.poetryfoundation.org/poems/44272/the-road-not-taken", inputMode = "url", class_name="text-dark"),
                        html.Br(),
                    ]
                ),
            ),
            dbc.ModalFooter([
                dbc.Button(
                    "Create Playbook", id="create-playbook-button", n_clicks=0, color="danger", style={'float': 'centre', 'margin-left': '10px'}
                ),
                dbc.Button(
                    "Close", id="pb-creator-modal-close-button", n_clicks=0, color="danger", style={'float': 'centre', 'margin-left': '10px'}
                ),
            ]
            ),
        ],
        id="playbook-creator-modal",
        is_open=False,
    ),
    dbc.Offcanvas(
        id="pb-technique-info-offcanvas",
        title="Attack Technique Info",
        placement = "end",
        scrollable=True,
        is_open=False,
    ),
    
], className="bg-dark", style={"height": "100vh", 'overflow': 'auto', "padding-right": "20px", "padding-left": "20px"})
