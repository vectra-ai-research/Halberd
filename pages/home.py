'''
Page Navigation url : app/home

Page Description : Hosts the launch page of Halberd. Displays information regarding the tool and overview of included modules.
'''

from dash import html

# define home page layout
page_layout = html.Div([
    html.Br(),
    html.Br(),
    html.Div(
        html.Img(src= "/assets/halberd_nbg_lg.png", style={'height':'15%', 'width':'15%'}),
    ),
    html.Br(),
    html.Div([
        html.P(html.H1("Halberd | Security Testing")),
        html.Br(),
    ], style={"padding-right": "100px", "padding-left": "100px"}),
    html.Br(),
    html.Br(),
],className="bg-dark", style={"textAlign": "center", "height": "90vh", "justify-content": "center", "align-items": "center"})