from dash import dcc,html

page_layout = html.Div(
    [
        html.Br(),
        html.Br(),
        html.H2("Entra ID / M365 - Access Info", style ={"textAlign": "center", "padding": "5px"}),
        html.Div([
            html.H4("Set Access Token"),
            dcc.Dropdown(id="token-selector-dropdown"),
            html.Br(), 
        ]),
        html.Div([
            html.H2("Access Info"),
            dcc.Loading(
                    id="access-info-loading",
                    type="default",
                    children=html.Div(id="access-info-div", style={"border":"1px solid #ccc", "padding-right": "10px", "padding-left": "10px"})
                ),
            html.Br(),
        ]),

        html.Br(),
        html.Br(),
        html.H2("AWS - Access Info", style ={"textAlign": "center", "padding": "5px"}),
        html.Div([
            html.H4("Set Access Client"),
            dcc.Dropdown(id="aws-client-selector-dropdown"),
            html.Br(), 
        ]),
        html.Div([
            html.H2("Access Info"),
            dcc.Loading(
                    id="aws-access-info-loading",
                    type="default",
                    children=html.Div(id="aws-access-info-div", style={"border":"1px solid #ccc", "padding-right": "10px", "padding-left": "10px"})
                ),
            html.Br(),
        ]),
    ],
    className="bg-dark",style={ "height": "100vh", "padding-right": "20px", "padding-left": "20px"}
)