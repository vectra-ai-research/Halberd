'''
Name : TabContentGenerator.py
Description : Generates 'Attack' page content based on the attack surface tab selected. Returns output to 'tabs-content-div'.
'''
import dash_bootstrap_components as dbc
from dash import dcc,html
import yaml


def TabContentGenerator(tab):
    tab_content_elements = []

    # load all tactics information for each attack surface from the TacticsMap.yml file
    tactics_map_file = "./Techniques/TacticsMap.yml"

    with open(tactics_map_file, "r") as tactics_file_data:
        tactics_map = yaml.safe_load(tactics_file_data)

    # from tab selected, create tactics dropdown list from the available tactics in the attack surface
    if tab == "tab-attack-M365":
        tactics_options = tactics_map['M365_Tactics']
    if tab == "tab-attack-EntraID":
        tactics_options = tactics_map['Entra_Id_Tactics']
    if tab == "tab-attack-Azure":
        tactics_options = tactics_map['Azure_Tactics']
    if tab == "tab-attack-AWS":
        tactics_options = tactics_map['AWS_Tactics']
    
    # create the dropdown element
    tactic_dropdown_option = []    
    for tactic in tactics_options:
        tactic_dropdown_option.append(
            {
                "label": html.Div([tactic], style={'font-size': 20}, className="text-dark"),
                "value": tactic,
            }
        )    

    tab_content_elements.append(dcc.Dropdown(options = tactic_dropdown_option, value = tactic_dropdown_option[0]["value"], id='tactic-dropdown'))
    tab_content_elements.append(html.Br())

    # add element to display technique options under each tactic
    tab_content_elements.append(
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
    tab_content_elements.append(html.Br())
    tab_content_elements.append(html.Br())

    # add element to display output of executed technique
    tab_content_elements.append(html.H4("Response"))
    tab_content_elements.append(
        dcc.Loading(
            id="attack-output-loading",
            type="default",
            children=html.Div(id= "execution-output-div",style={"height":"40vh", "overflowY": "auto", "border":"1px solid #ccc", "padding-right": "10px", "padding-left": "10px", "padding-top": "10px", "padding-bottom": "10px"})
        )
    )

    # final tab div to return
    tab_content = html.Div(
        tab_content_elements,
        style={"height":"87vh", "padding-right": "20px", "padding-left": "20px", "padding-top": "20px", "padding-bottom": "20px"}, 
        className="bg-dark"
    )

    return tab_content