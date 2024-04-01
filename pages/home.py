'''
Page Navigation url : app/home

Page Description : Hosts the launch page of Halberd. Displays information regarding the tool and overview of included modules.
'''

import dash_bootstrap_components as dbc
from dash import html
import dash_daq as daq
import os

# folder list
folders = ['EntraID','M365','AWS']

# initiate counter for modules
module_count = 0

# enumerate all techniques folders to count modules
for folder in folders:
    for module_file in os.listdir(f"./Techniques/{folder}"):
        if module_file.endswith(".py"):
            module_count += 1

# define home page layout
page_layout = html.Div([
    html.Br(),
    html.Br(),
    html.Div(
        html.Img(src= "/assets/halberd_nbg_lg.png", style={'height':'15%', 'width':'15%'}),
    ),
    html.Br(),
    html.Div([
        html.P(html.H1("Offensive Security Testing Framework")),
        html.Br(),
        html.H4("Attack using a comprehensive array of executable attack techniques."),
        html.Br(),
        html.H4("Evaluate defenses across attack vectors, including Entra ID, M365, Azure and AWS."),
        html.Br(),
        html.H4("Test with an intuitive web interface that puts effective security testing at your fingertips."),
        html.Br(),

    ], style={"padding-right": "100px", "padding-left": "100px"}),
    html.Br(),
    html.Br(),
    html.Div([
        dbc.Row([
            dbc.Col([
                html.H3("Surface"),
                daq.LEDDisplay(
                    id='surfaces-LED-display-1',
                    value="03",
                    size=80,
                    color = "Black"
                ),
            ], style={'height': '200px'},),

            dbc.Col([
                html.H3("Tactics"),
                daq.LEDDisplay(
                    id='tactics-LED-display-1',
                    value="08",
                    size=80,
                    color = "Black"
                ),
            ], style={'height': '200px'},),

            dbc.Col([
                html.H3("Modules"),
                daq.LEDDisplay(
                    id='techniques-LED-display-1',
                    value = module_count,
                    size=80,
                    color = "Black"
                ),
            ], style={'height': '200px'},),
        ])
    ]),
],className="bg-dark", style={"textAlign": "center", "height": "100vh", "justify-content": "center", "align-items": "center"})