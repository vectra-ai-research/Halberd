#!/usr/bin/env python3
import dash
from dash import dcc, html, page_container
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc

from core.entra.entra_token_manager import EntraTokenManager

entra_token_manager = EntraTokenManager() # Initialize Entra token manager
entra_token_manager._monitor_thread.start() #Start token refresh monitoring

# Create Halberd application
app = dash.Dash(
    __name__,  
    external_stylesheets=[dbc.themes.LUX, dbc.icons.BOOTSTRAP],
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
                "Recon", 
                href="/recon",
                id="nav-recon",
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
        )
    ],
    brand= html.Div([
        dbc.Row(
                [
                    dbc.Col(html.Img(src="/assets/favicon.ico", height="30px")),
                    dbc.Col(html.Div("Halberd", className="halberd-brand")),
                ],
            ),
        ]),
    brand_href="/home",
    color="dark",
    dark=True,
    sticky= "top",
    className="bg-halberd-navbar mb-5",
    style={'min-height': '48px', 'padding': '4px 16px'}
)

# App layout
app.layout = html.Div([
    dcc.Interval(id='interval-to-trigger-initialization-check',interval=60000,n_intervals=0),
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
    )
])

'''Callback to update the Navbar content based on the URL'''
@app.callback(
    [
        Output("nav-attack", "className"),
        Output("nav-recon", "className"),
        Output("nav-automator", "className"),
        Output("nav-analyse", "className")
    ],
    Input('url', 'pathname')
)
def update_nav_style(pathname):
    # Active style adds Halberd red color to selected item
    active_className = "halberd-brand text-xl"
    
    # Default style
    styles = ["halberd-brand-heading"] * 4
    
    if pathname == '/attack':
        styles[0] = active_className
    elif pathname == '/recon':
        styles[1] = active_className
    elif pathname == '/automator':
        styles[2] = active_className
    elif pathname == '/attack-analyse':
        styles[3] = active_className
        
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