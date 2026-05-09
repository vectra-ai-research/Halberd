#!/usr/bin/env python3
import dash
import os
import json
from dash import dcc, html, page_container, ALL, callback_context
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify
from dotenv import set_key

from core.entra.entra_token_manager import EntraTokenManager
from core.credential_manager import CredentialManager

entra_token_manager = EntraTokenManager() # Initialize Entra token manager
entra_token_manager._monitor_thread.start() #Start token refresh monitoring

# Create Halberd application
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.LUX, dbc.icons.BOOTSTRAP, dbc.icons.FONT_AWESOME],
    title='Halberd',
    update_title='Loading...',
    use_pages=True,
    suppress_callback_exceptions=True
    )

# Navigation bar layout
navbar = dbc.NavbarSimple(
    id = "halberd-main-navbar",
    children=[
        dbc.NavItem(
            dbc.NavLink(
                "Attack",
                href="/attack",
                id="nav-attack",
                className="nav-link",
                style={"font-weight": "500"}
            )
        ),
        dbc.NavItem(
            dbc.NavLink(
                "Automator",
                href="/automator",
                id="nav-automator",
                className="nav-link",
                style={"font-weight": "500"}
            )
        ),
        dbc.NavItem(
            dbc.NavLink(
                "Analyse",
                href="/attack-analyse",
                id="nav-analyse",
                className="nav-link",
                style={"font-weight": "500"}
            )
        ),
        dbc.NavItem(
            dbc.NavLink(
                "Agent",
                href="/attack-agent",
                id="nav-agent",
                className="nav-link",
                style={"font-weight": "500"}
            )
        ),
        dbc.NavItem(
            dbc.DropdownMenu(
                id="credential-status-dropdown",
                label=html.Div([
                    DashIconify(icon="mdi:key-chain", height=20, width=20, className="me-2"),
                    html.Span("Credentials", id="credential-count-display")
                ], className="d-flex align-items-center"),
                children=[
                    dbc.DropdownMenuItem("None Available", id="credential-dropdown-content")
                ],
                nav=True,
                in_navbar=True,
                className="credential-dropdown",
                caret=False
            )
        ),
        dbc.NavItem(
            dbc.NavLink(
                dbc.Button([
                    DashIconify(icon="mdi:cog",height=20, width=20, className="m-0")],
                    id= "settings-button",
                    className="border-0 bg-transparent"
                ),
                id="nav-settings",
                className="nav-link p-0"
            )
        ),
    ],
    brand= html.Div([
        dbc.Row(
                [
                    dbc.Col(html.Img(src="/assets/favicon.ico", height="30px")),
                    dbc.Col(html.Div("Halberd", className="halberd-brand")),
                ],
            ),
        ]),
    brand_href="/",
    color="dark",
    dark=True,
    sticky= "top",
    className="bg-halberd-dark mb-2",
    style={'min-height': '48px', 'padding': '4px 16px'}
)

# Generate settings off canvas
def generate_settings_offcanvas():
    """Generate off-canvas components for app settings"""
    return [
        dbc.Form([
            dbc.Col([
                dbc.Accordion([
                    dbc.AccordionItem([
                        dbc.Row([
                            dbc.Col([
                                html.Div([
                                    dbc.Label(["Anthropic API Key", DashIconify(icon= "mdi:information", className="ms-2", id = "anthropic-api-key-info-icon")]),
                                    dbc.Popover(
                                        "Required to enable Halberd Attack Agent",
                                        target="anthropic-api-key-info-icon",
                                        body=True,
                                        trigger="hover",
                                    ),
                                ])
                            ]),
                            dbc.Col([
                                dcc.Link(["Generate API Key", DashIconify(icon="mdi:open-in-new", className="ms-2")], href= "https://console.anthropic.com/settings/keys", target="_blank", className="halberd-link float-end")
                            ])
                        ]),
                        dbc.Input(
                            type="password",
                            id="anthropic-api-key-input-editor",
                            placeholder="Enter API Key",
                            className="bg-halberd-dark halberd-input halberd-text mb-4"
                        ),
                        dbc.Fade(
                            id="anthropic-api-key-fade",
                            is_in=False,
                            appear=False,
                        ),
                    ], title="Halberd Attack Agent", className="mb-4 bg-halberd-dark enhanced-accordion")
                ]),
            ])
        ]),
        # Save settings button
        dbc.Button(
            [
                DashIconify(icon="mdi:content-save-cog", className="me-2"),
                "Save"
            ],
            id="save-settings-button",
            className="w-100 halberd-button"
        )
    ]

# App layout
app.layout = html.Div([
    dcc.Interval(id='interval-to-trigger-initialization-check',interval=60000,n_intervals=0),
    dcc.Interval(id='credential-status-update-interval',interval=30000,n_intervals=0),
    html.Div(id='hidden-div', style={'display':'none'}),
    dcc.Location(id='url', refresh=False),
    navbar,
    page_container,
    dbc.Toast(
        children = "Hello!",
        id="app-welcome-notification",
        header="Welcome to Halberd",
        is_open=True,
        dismissable=True,
        duration=3000,
        color="primary",
        style={"position": "fixed", "top": 92, "right": 10, "width": 350},
    ),
    dbc.Toast(
        children = "",
        id="app-notification",
        header="Notification",
        is_open=False,
        dismissable=True,
        duration=5000,
        color="primary",
        style={"position": "fixed", "top": 92, "right": 10, "width": 350},
    ),
    dbc.Modal(
        [
            dbc.ModalHeader(dbc.ModalTitle("Credential Details", className="halberd-brand")),
            dbc.ModalBody(id="credential-details-modal-body"),
            dbc.ModalFooter([
                dbc.Button("Set as Active", id="set-active-credential-btn", className="halberd-button me-2"),
                dbc.Button("Delete Credential", id="delete-credential-btn", className="halberd-button-secondary me-2"),
                dbc.Button("Close", id="close-credential-details-modal", className="halberd-button-secondary")
            ])
        ],
        id="credential-details-modal",
        size="lg",
        is_open=False,
    ),
    dcc.Download(id="app-download-sink"),
    dbc.Modal(
        [
            dbc.ModalHeader(dbc.ModalTitle("Technique Details")),
            dbc.ModalBody(id = "app-technique-info-display-modal-body"),
            dbc.ModalFooter(
                dbc.Button("Close", id="close-app-technique-info-display-modal", className="ml-auto")
            ),
        ],
        id="app-technique-info-display-modal",
        size="lg",
        scrollable=True,
    ),
    # Error modal -> use this to display an error pop up message
    dbc.Modal(
    [
        dbc.ModalHeader("Error", style={"background-color": "#dc3545", "color": "white"}),
        dbc.ModalBody(id="app-error-display-modal-body"),
        dbc.ModalFooter(
            dbc.Button("Close", id="close-app-error-display-modal", className="ml-auto")
        ),
    ],
    id="app-error-display-modal",
    is_open=False,
    ),
    # Success modal -> use this to display a success pop up message
    dbc.Modal(
    [
        dbc.ModalHeader("Success", style={"background-color": "#28a745", "color": "white"}),
        dbc.ModalBody(id="app-success-display-modal-body"),
        dbc.ModalFooter(
            dbc.Button("Close", id="close-app-success-display-modal", className="ml-auto")
        ),
    ],
    id="app-success-display-modal",
    is_open=False,
    ),
    dbc.Offcanvas(
        children = generate_settings_offcanvas(),
        id="settings-offcanvas",
        title = html.H3("Halberd Settings"),
        is_open=False,
        placement="end",
        style={
            "width": "50%",
            "max-width": "none",
        },
        className="bg-halberd-dark halberd-offcanvas halberd-text"
    )
], className="bg-halberd-dark")

'''Callback to update the Navbar content based on the URL'''
@app.callback(
    [
        Output("nav-attack", "className"),
        Output("nav-recon", "className"),
        Output("nav-automator", "className"),
        Output("nav-analyse", "className"),
        Output("nav-agent", "className")
    ],
    Input('url', 'pathname')
)
def update_nav_style(pathname):
    # Active style adds Halberd red color to selected item
    active_className = "halberd-brand text-xl"

    # Default style
    styles = ["halberd-brand-heading"] * 5

    if pathname == '/attack':
        styles[0] = active_className
    elif pathname == '/recon':
        styles[1] = active_className
    elif pathname == '/automator':
        styles[2] = active_className
    elif pathname == '/attack-analyse':
        styles[3] = active_className
    elif pathname == '/attack-agent':
        styles[4] = active_className

    return styles

'''Callback to close the app technique info modal'''
@app.callback(
    Output("app-technique-info-display-modal", "is_open", allow_duplicate=True),
    Input("close-app-technique-info-display-modal", "n_clicks"),
    State("app-technique-info-display-modal", "is_open"),
    prevent_initial_call=True
)
def close_app_t_info_modal_callback(n_clicks, is_open):
    if n_clicks:
        return False
    return is_open

'''Callback to close the app error modal'''
@app.callback(
    Output("app-error-display-modal", "is_open", allow_duplicate=True),
    Input("close-app-error-display-modal", "n_clicks"),
    State("app-error-display-modal", "is_open"),
    prevent_initial_call=True
)
def close_app_error_modal_callback(n_clicks, is_open):
    if n_clicks:
        return False
    return is_open

'''Callback to open app settings off canvas'''
@app.callback(
        Output(component_id = "settings-offcanvas", component_property = "is_open", allow_duplicate= True),
        Input('settings-button', 'n_clicks'),
        prevent_initial_call=True
)
def toggle_pb_schedule_canvas_callback(n_clicks):
    if not n_clicks:
        raise PreventUpdate

    return True

@app.callback(
    Output(component_id = "anthropic-api-key-fade", component_property = "is_in", allow_duplicate=True),
    Output(component_id = "anthropic-api-key-fade", component_property = "children", allow_duplicate=True),
    Output('anthropic-api-key-input-editor', 'value'),
    Input('save-settings-button', 'n_clicks'),
    State('anthropic-api-key-input-editor', 'value'),
    prevent_initial_call=True
)
def save_api_key_to_env_dotenv(n_clicks, api_key_value):
    """
    Callback to save the Anthropic API key to .env file
    """
    if not n_clicks:
        raise PreventUpdate

    if not api_key_value or api_key_value.strip() == "":
        return True, html.Div("Please enter a valid API key", className="text-danger"), ""

    env_file_path = ".env"

    try:
        # Create .env file if it doesn't exist
        if not os.path.exists(env_file_path):
            with open(env_file_path, 'w'):
                pass  # Create empty file

        # Set the API key in .env file
        set_key(env_file_path, "ANTHROPIC_API_KEY", api_key_value.strip())

        return True, html.Div("API key saved successfully!", className="text-success"), ""

    except Exception as e:
        return True, html.Div(f"Error saving API key: {str(e)}", className="text-danger"), ""

def generate_credential_dropdown_content():
    """Generate credential dropdown content and count display for all providers"""
    return CredentialManager.get_dropdown_content()

# Store current credential for modal actions
current_modal_credential = None
current_modal_provider = None

'''Callback to update credential status display'''
@app.callback(
    [Output("credential-count-display", "children"),
     Output("credential-dropdown-content", "children")],
    Input("credential-status-update-interval", "n_intervals")
)
def update_credential_status(n_intervals):
    return generate_credential_dropdown_content()

'''Callback to close credential details modal'''
@app.callback(
    Output("credential-details-modal", "is_open", allow_duplicate=True),
    Input("close-credential-details-modal", "n_clicks"),
    prevent_initial_call=True
)
def close_credential_details_modal(n_clicks):
    if n_clicks:
        return False
    raise PreventUpdate

'''Callback to set active credential from modal'''
@app.callback(
    [Output("app-notification", "is_open", allow_duplicate=True),
     Output("app-notification", "children", allow_duplicate=True),
     Output("app-notification", "header", allow_duplicate=True),
     Output("app-notification", "color", allow_duplicate=True),
     Output("credential-details-modal", "is_open", allow_duplicate=True)],
    Input("set-active-credential-btn", "n_clicks"),
    prevent_initial_call=True
)
def set_active_credential_from_modal(n_clicks):
    global current_modal_credential, current_modal_provider
    if not n_clicks or not current_modal_credential or not current_modal_provider:
        raise PreventUpdate

    try:
        message = CredentialManager.set_active_credential(current_modal_provider, current_modal_credential)
        return True, message, "Success", "success", False
    except Exception as e:
        return True, f"Failed to set active credential: {str(e)}", "Error", "danger", False

'''Callback to delete credential directly from modal'''
@app.callback(
    [Output("app-notification", "is_open", allow_duplicate=True),
     Output("app-notification", "children", allow_duplicate=True),
     Output("app-notification", "header", allow_duplicate=True),
     Output("app-notification", "color", allow_duplicate=True),
     Output("credential-details-modal", "is_open", allow_duplicate=True)],
    Input("delete-credential-btn", "n_clicks"),
    prevent_initial_call=True
)
def delete_credential_from_modal(n_clicks):
    global current_modal_credential, current_modal_provider
    if not n_clicks or not current_modal_credential or not current_modal_provider:
        raise PreventUpdate

    try:
        message = CredentialManager.delete_credential(current_modal_provider, current_modal_credential.id, current_modal_credential)
        return True, message, "Success", "success", False
    except Exception as e:
        return True, f"Failed to delete credential: {str(e)}", "Error", "danger", False

'''Callback to delete any credential from dropdown (both valid and expired)'''
@app.callback(
    [Output("app-notification", "is_open", allow_duplicate=True),
     Output("app-notification", "children", allow_duplicate=True),
     Output("app-notification", "header", allow_duplicate=True),
     Output("app-notification", "color", allow_duplicate=True),
     Output("credential-count-display", "children", allow_duplicate=True),
     Output("credential-dropdown-content", "children", allow_duplicate=True)],
    [Input({"type": "delete-expired-credential", "credential_id": ALL, "provider": ALL}, "n_clicks"),
     Input({"type": "delete-credential", "credential_id": ALL, "provider": ALL}, "n_clicks")],
    prevent_initial_call=True
)
def delete_credential_from_dropdown(*n_clicks_lists):
    # Check if any button was clicked
    all_clicks = [click for clicks in n_clicks_lists if clicks for click in clicks]
    if not any(all_clicks):
        raise PreventUpdate

    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate

    try:
        # Parse the component ID to get the credential ID and provider
        triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]
        component_dict = json.loads(triggered_id)
        credential_id = component_dict['credential_id']
        provider = component_dict['provider']

        # Delete the credential
        message = CredentialManager.delete_credential(provider, credential_id)

        # Get refreshed credential status after deletion
        count_text, dropdown_items = generate_credential_dropdown_content()
        return True, message, "Success", "success", count_text, dropdown_items

    except Exception as e:
        # Get current credential status for UI refresh even on error
        count_text, dropdown_items = generate_credential_dropdown_content()
        return True, f"Failed to delete credential: {str(e)}", "Error", "danger", count_text, dropdown_items
