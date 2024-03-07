import dash_bootstrap_components as dbc
from dash import dcc,html
import yaml


def TabContentGenerator(tab):
    tab_container_elements = []

    tactics_map_file = "./Techniques/TacticsMap.yml"

    with open(tactics_map_file, "r") as tactics_file_data:
        tactics_map = yaml.safe_load(tactics_file_data)

    tab_container_elements.append(html.Div(id='attack-hidden-div', style={'display':'none'}))
    tab_container_elements.append(dcc.Store(id='attack-result-store'))

    if tab == "tab-attack-M365":
        tactics_options = tactics_map['M365_Tactics']
    if tab == "tab-attack-EntraID":
        tactics_options = tactics_map['Entra_Id_Tactics']
    if tab == "tab-attack-Azure":
        tactics_options = tactics_map['Azure_Tactics']
    if tab == "tab-attack-AWS":
        tactics_options = tactics_map['AWS_Tactics']
        
    tactic_dropdown_option = []    
    for tactic in tactics_options:
        tactic_dropdown_option.append(
            {
                "label": html.Div([tactic], style={'font-size': 20}, className="text-dark"),
                "value": tactic,
            }
        )    

    tab_container_elements.append(dcc.Dropdown(options = tactic_dropdown_option, value = tactic_dropdown_option[0]["value"], id='tactic-dropdown'))
    tab_container_elements.append(html.Br())
    tab_container_elements.append(
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Div(id = "technique-options-div", className= "bg-dark"),
                ], width = 3),
                dbc.Col([
                    html.Div(id= "attack-config-div",className='bg-dark divBorder d-grid col-6 mx-auto', style={'width' : '100%'}),
                ], width = 7),
            ])  
        ])
    )
    tab_container_elements.append(html.Br())
    tab_container_elements.append(html.Br())
    tab_container_elements.append(html.H4("Response"))
    tab_container_elements.append(
        dcc.Loading(
            id="attack-output-loading",
            type="default",
            children=html.Div(id= "execution-output-div",style={"height":"30vh", "overflowY": "scroll", "border":"1px solid #ccc"})
        )
    )

    tab_content = dbc.Container(
        html.Div(tab_container_elements, style={"height":"87vh"}, className="bg-dark"),
        fluid=True,
        className="mt-4 advanced-homepage",
        style={"height":"87vh"}
    )

    return tab_content