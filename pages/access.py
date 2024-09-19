from dash import dcc, html
import dash_bootstrap_components as dbc

def create_access_section(title, dropdown_id, remove_button_id, info_div_id):
    """Dynamically creates access info sections on Access page"""
    return dbc.Card(
        dbc.CardBody([
            html.H3(title, className="text-success mb-3"),
            dbc.Row([
                dbc.Col([
                    html.H4("Set Access", className="mb-2"),
                    dcc.Dropdown(id=dropdown_id, className="mb-2"),
                    html.Br(),
                    dbc.Button("Remove Access", id=remove_button_id, color="danger", size="sm", className="mt-2"),
                ], md=4),
                dbc.Col([
                    dcc.Loading(
                        id=f"{info_div_id}-loading",
                        type="default",
                        children=html.Div(id=info_div_id, className="border rounded p-3 bg-dark")
                    )
                ], md=8),
            ]),
        ]),
        className="mb-4",
        style={"backgroundColor": "#343a40", "color": "white"}
    )

page_layout = html.Div(
    [
        html.H2("Access Manager", className="text-success mb-3"),
        create_access_section(
            "Entra ID / M365 - Access Info",
            "token-selector-dropdown",
            "del-entra-token-button",
            "access-info-div"
        ),
        create_access_section(
            "AWS - Access Info",
            "aws-session-selector-dropdown",
            "del-aws-session-button",
            "aws-access-info-div"
        ),
        create_access_section(
            "Azure - Access Info",
            "azure-subscription-selector-dropdown",
            "del-az-session-button",
            "azure-access-info-div"
        ),
    ],
    className="bg-dark",
    style={"minHeight": "100vh", "padding": "20px"}
)