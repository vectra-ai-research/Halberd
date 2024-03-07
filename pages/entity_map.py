from dash import html, dcc
import dash_bootstrap_components as dbc


page_layout = html.Div([
    dbc.Button("Generate Entity Map", id="generate-entity-map-button", n_clicks=0, color="danger", style={'float': 'right', 'margin-left': '10px'}),
    dcc.Loading(
        id="attack-output-loading",
        type="default",
        children = html.Div(id = "entity-map-display-div", style= {"height": "100vh"})
    ),
    ],className = "bg-dark")