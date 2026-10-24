#!/usr/bin/env python3
import dash
import os
from dash import dcc, html, page_container
from dash.dependencies import Input, Output, State
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
from dash_iconify import DashIconify
from dotenv import set_key

from core.entra.entra_token_manager import EntraTokenManager
from core.orcarouter import runtime
from core.orcarouter.config import (
    PROVIDER_CYBER_MODELS,
    PROVIDER_CYBER_PAGE,
    PROVIDER_HOME,
    PROVIDER_KEY_PAGE,
)
from core.orcarouter.credentials import CredentialError
from core.orcarouter.providers import provider_options

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

# ---------------------------------------------------------------------------
# OrcaRouter Cyber Inference settings
# ---------------------------------------------------------------------------
_SOURCE_LABELS = {"api_key": "API key", "pkce": "OAuth 2.0 + PKCE", "env": "environment"}


def _credential_status_children():
    """Render the stored credential without ever revealing the secret."""
    status = runtime.credential_store().status()
    if not status["configured"]:
        return html.Span(
            "Not connected. Save an API key or connect with OrcaRouter.",
            className="text-warning",
        )
    source = _SOURCE_LABELS.get(status["source"], status["source"] or "stored credential")
    children = [
        html.Span("Connected via "),
        html.Span(source, className="fw-bold"),
        html.Span(" · "),
        html.Code(status["masked"], className="halberd-text"),
    ]
    if status["needs_reauth"]:
        children.append(html.Span(" · reauthentication required", className="text-danger"))
    return html.Span(children)


# Generate settings off canvas
def generate_settings_offcanvas():
    """Generate off-canvas components for app settings"""
    return [
        dbc.Form([
            dbc.Col([
                dbc.Accordion([
                    dbc.AccordionItem([
                        html.Div([
                            dbc.Label("Agent provider"),
                            dcc.Dropdown(
                                id="agent-provider-selector",
                                options=provider_options(),
                                value=runtime.get_agent_settings().provider(),
                                clearable=False,
                                className="halberd-dropdown mb-3",
                            ),
                        ]),
                        # ------------------------------------------------ Anthropic
                        html.Div([
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
                                    dcc.Link(["Genereate API Key", DashIconify(icon="mdi:open-in-new", className="ms-2")], href= "https://console.anthropic.com/settings/keys", target="_blank", className="halberd-link float-end")
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
                        ], id="anthropic-settings-section"),
                        # ----------------------------------------------- OrcaRouter
                        html.Div([
                            html.Hr(className="border-secondary"),
                            dbc.Row([
                                dbc.Col([
                                    html.Div([
                                        html.Img(src="/assets/orcarouter-logo.png", height="22px", className="me-2"),
                                        html.Span("OrcaRouter Cyber Inference", className="fw-bold halberd-text"),
                                    ], className="d-flex align-items-center"),
                                    html.Div(
                                        "Named inference provider for authorized security work: cyber models for "
                                        "red teams and gateway-level controls for blue teams on one endpoint.",
                                        className="halberd-text small mt-2 mb-1",
                                    ),
                                    html.Div([
                                        dcc.Link("Provider overview", href=PROVIDER_CYBER_PAGE, target="_blank", className="halberd-link small me-3"),
                                        dcc.Link("Cyber model catalog", href=PROVIDER_CYBER_MODELS, target="_blank", className="halberd-link small me-3"),
                                        dcc.Link("API keys", href=PROVIDER_KEY_PAGE, target="_blank", className="halberd-link small"),
                                    ], className="mb-3"),
                                ])
                            ]),
                            html.Div(_credential_status_children(), id="orcarouter-credential-status", className="halberd-text small mb-3"),
                            dbc.Row([
                                # Choice 1: existing API key
                                dbc.Col([
                                    dbc.Card([
                                        dbc.CardBody([
                                            html.Div([DashIconify(icon="mdi:key-variant", className="me-2"), "OrcaRouter - API"], className="fw-bold halberd-text mb-2"),
                                            dbc.Input(
                                                type="password",
                                                id="orcarouter-api-key-input-editor",
                                                placeholder="sk-orca-...",
                                                className="bg-halberd-dark halberd-input halberd-text mb-2",
                                            ),
                                            html.Div([
                                                dbc.Button("Save API key", id="orcarouter-save-key-button", size="sm", className="halberd-button me-2"),
                                                dbc.Button("Clear", id="orcarouter-clear-key-button", size="sm", className="action-button"),
                                            ]),
                                        ])
                                    ], className="h-100 halberd-depth-card")
                                ], width=6),
                                # Choice 2: OAuth 2.0 + PKCE
                                dbc.Col([
                                    dbc.Card([
                                        dbc.CardBody([
                                            html.Div([DashIconify(icon="mdi:shield-account", className="me-2"), "OrcaRouter - Auth"], className="fw-bold halberd-text mb-2"),
                                            html.Div("Sign in with your OrcaRouter account. No client secret, PKCE (S256) loopback redirect.", className="small halberd-text mb-2"),
                                            html.Div([
                                                dbc.Button("Connect with OrcaRouter", id="orcarouter-connect-button", size="sm", className="halberd-button me-2"),
                                                dbc.Button("Cancel", id="orcarouter-cancel-button", size="sm", className="action-button"),
                                            ]),
                                            html.Div(
                                                dcc.Link("Open the authorization page", id="orcarouter-auth-link", href="#", target="_blank", className="halberd-link small d-none mt-2"),
                                                id="orcarouter-auth-link-wrap",
                                                className="mt-2",
                                            ),
                                        ])
                                    ], className="h-100 halberd-depth-card")
                                ], width=6),
                            ], className="g-2"),
                            html.Div(id="orcarouter-auth-status", className="small mt-2"),
                            dcc.Interval(id="orcarouter-auth-poll", interval=1200, disabled=True),
                        ], id="orcarouter-settings-section", style={"display": "none"}),
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
    html.Div(id='hidden-div', style={'display':'none'}),
    dcc.Location(id='url', refresh=False),
    dcc.Store(id="agent-provider-store", data=runtime.get_agent_settings().snapshot()),
    dcc.Store(id="orcarouter-pagehide-sentinel"),
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
            with open(env_file_path, 'w') as file:
                pass  # Create empty file
        
        # Set the API key in .env file
        set_key(env_file_path, "ANTHROPIC_API_KEY", api_key_value.strip())
        
        return True, html.Div("API key saved successfully!", className="text-success"), ""
    
    except Exception as e:
        return True, html.Div(f"Error saving API key: {str(e)}", className="text-danger"), ""


@app.callback(
    Output("anthropic-settings-section", "style"),
    Output("orcarouter-settings-section", "style"),
    Output("agent-provider-store", "data"),
    Input("agent-provider-selector", "value"),
)
def sync_provider_sections(provider_id):
    provider = provider_id or "anthropic"
    is_orca = provider == "orcarouter"
    snapshot = runtime.get_agent_settings().snapshot()
    snapshot["provider"] = provider
    return (
        {"display": "none"} if is_orca else {},
        {} if is_orca else {"display": "none"},
        snapshot,
    )


@app.callback(
    Output("orcarouter-credential-status", "children"),
    Input("agent-provider-selector", "value"),
    prevent_initial_call=True,
)
def provider_changed(provider_id):
    """Switching provider or auth method releases any in-flight login."""
    runtime.auth_manager().cancel()
    runtime.get_agent_settings().set_provider(provider_id or "anthropic")
    return _credential_status_children()


@app.callback(
    Output("orcarouter-credential-status", "children", allow_duplicate=True),
    Output("orcarouter-auth-status", "children", allow_duplicate=True),
    Output("orcarouter-api-key-input-editor", "value"),
    Input("orcarouter-save-key-button", "n_clicks"),
    State("orcarouter-api-key-input-editor", "value"),
    prevent_initial_call=True,
)
def save_orcarouter_api_key(n_clicks, api_key_value):
    if not n_clicks:
        raise PreventUpdate
    try:
        credential = runtime.credential_store().save_api_key(api_key_value or "")
    except CredentialError as exc:
        return _credential_status_children(), html.Span(str(exc), className="text-danger"), dash.no_update
    runtime.catalog_service().invalidate()
    return (
        _credential_status_children(),
        html.Span(f"API key saved ({credential.masked}).", className="text-success"),
        "",
    )


@app.callback(
    Output("orcarouter-credential-status", "children", allow_duplicate=True),
    Output("orcarouter-auth-status", "children", allow_duplicate=True),
    Input("orcarouter-clear-key-button", "n_clicks"),
    prevent_initial_call=True,
)
def clear_orcarouter_credential(n_clicks):
    if not n_clicks:
        raise PreventUpdate
    runtime.auth_manager().cancel()
    runtime.credential_store().clear()
    runtime.catalog_service().invalidate()
    return _credential_status_children(), html.Span(
        "OrcaRouter credential cleared.", className="text-success"
    )


@app.callback(
    Output("orcarouter-auth-status", "children"),
    Output("orcarouter-auth-link", "href"),
    Output("orcarouter-auth-link-wrap", "className"),
    Output("orcarouter-auth-poll", "disabled"),
    Input("orcarouter-connect-button", "n_clicks"),
    prevent_initial_call=True,
)
def start_orcarouter_connect(n_clicks):
    if not n_clicks:
        raise PreventUpdate
    attempt = runtime.auth_manager().begin(open_browser=True)
    return (
        html.Span(
            "Waiting for approval in your browser. Open the authorization page if it did not appear.",
            className="text-info",
        ),
        attempt["authorize_url"],
        "mt-2",
        False,
    )


@app.callback(
    Output("orcarouter-auth-status", "children", allow_duplicate=True),
    Output("orcarouter-auth-poll", "disabled", allow_duplicate=True),
    Output("orcarouter-credential-status", "children", allow_duplicate=True),
    Output("orcarouter-auth-link-wrap", "className", allow_duplicate=True),
    Input("orcarouter-auth-poll", "n_intervals"),
    prevent_initial_call=True,
)
def poll_orcarouter_connect(n_intervals):
    attempt = runtime.auth_manager().status()
    state = attempt["state"]
    if state == "pending":
        return (
            html.Span("Waiting for approval in your browser...", className="text-info"),
            False,
            dash.no_update,
            "mt-2",
        )
    if state == "success":
        runtime.catalog_service().invalidate()
        return (
            html.Span(attempt["message"], className="text-success"),
            True,
            _credential_status_children(),
            "d-none",
        )
    if state in ("error", "cancelled", "stale"):
        return (
            html.Span(attempt["message"] or "Authorization did not complete.", className="text-danger"),
            True,
            dash.no_update,
            "d-none",
        )
    return dash.no_update, True, dash.no_update, "d-none"


@app.callback(
    Output("orcarouter-auth-status", "children", allow_duplicate=True),
    Output("orcarouter-auth-poll", "disabled", allow_duplicate=True),
    Output("orcarouter-auth-link-wrap", "className", allow_duplicate=True),
    Input("orcarouter-cancel-button", "n_clicks"),
    prevent_initial_call=True,
)
def cancel_orcarouter_connect(n_clicks):
    if not n_clicks:
        raise PreventUpdate
    attempt = runtime.auth_manager().cancel()
    return html.Span(attempt["message"], className="text-muted"), True, "d-none"


# A page that is being hidden for the back-forward cache must clear its busy
# state synchronously: the invalidated server request will (correctly) refuse
# to touch state from its ``finally`` block.
app.clientside_callback(
    """
    function(pathname) {
        if (!window.__halberdOrcaPagehide) {
            window.__halberdOrcaPagehide = true;
            window.addEventListener('pagehide', function () {
                try {
                    fetch('/orcarouter/auth/cancel?pagehide=1', {method: 'POST', keepalive: true});
                } catch (e) {}
                var status = document.getElementById('orcarouter-auth-status');
                if (status) { status.textContent = 'Authorization cancelled (page closed).'; }
                var link = document.getElementById('orcarouter-auth-link-wrap');
                if (link) { link.className = 'd-none'; }
            });
        }
        return window.dash_clientside.no_update;
    }
    """,
    Output("orcarouter-pagehide-sentinel", "data"),
    Input("url", "pathname"),
)


@app.server.route("/orcarouter/auth/cancel", methods=["POST", "GET"])
def orcarouter_auth_cancel():
    from flask import jsonify, request as flask_request

    pagehide = flask_request.args.get("pagehide") in ("1", "true", "yes")
    status = runtime.auth_manager().cancel(pagehide=pagehide)
    return jsonify({"state": status["state"]})
