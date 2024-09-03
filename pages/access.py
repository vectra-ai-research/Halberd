'''
Page Navigation url : app/access

Page Description : Page functions as an access manager for Halberd. Displays real time access information to various cloud services and provides options to manage access. The information on the page is dynamically generated through series of callbacks - C010, C011.
'''

from dash import dcc,html

page_layout = html.Div(
    [
        html.H2("Access Manager", className="text-success mb-3"),
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
            html.H4("Set AWS Session"),
            dcc.Dropdown(id="aws-session-selector-dropdown"),
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

        html.Br(),
        html.Br(),
        html.H2("Azure - Access Info", style ={"textAlign": "center", "padding": "5px"}),
        html.Div([
            html.H4("Set Default Subscription"),
            dcc.Dropdown(id="azure-subscription-selector-dropdown"),
            html.Br(), 
        ]),
        html.Div([
            html.H2("Access Info"),
            dcc.Loading(
                    id="azure-access-info-loading",
                    type="default",
                    children=html.Div(id="azure-access-info-div", style={"border":"1px solid #ccc", "padding-right": "10px", "padding-left": "10px"})
                ),
            html.Br(),
        ]),
    ],
    className="bg-dark",style={ "height": "100vh", "padding-right": "20px", "padding-left": "20px"}
)