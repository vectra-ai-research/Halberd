'''
Page Navigation url : app/attack-trace
Page Description : Page displays a log of executed modules and allows exporting the data in a csv format. The logs are generated from local/Trace_Log.csv which is created locally on the users host.  
'''

from dash import html
import dash_bootstrap_components as dbc
from csv import DictReader 
from core.Constants import TRACE_LOG_FILE

def GenerateAttackTraceView():

    # Load trace log file
    f = open(TRACE_LOG_FILE,"r")
    log_data = list(DictReader(f))

    # load last 20 events
    latest_events = log_data[-20:]
    
    # set table headers
    table_header = [
        html.Thead(html.Tr([html.Th("Timestamp"), html.Th("Attack Surface"), html.Th("Tactic"), html.Th("Technique"), html.Th("Result")]))
    ]

    # add table entries
    table_entries = []
    for event in latest_events:
        table_entries.append(
            html.Tr([html.Td(event['date_time']), html.Td(event['attack_surface']), html.Td(event['tactic']), html.Td(event['technique']), html.Td(event['result'])])
        )

    table_body = [html.Tbody(table_entries)]
    table_content = table_header + table_body

    # Generate attack trace page layout
    return html.Div([
        dbc.Row([
            dbc.Col(
                html.H2("Attack Trace - Event Timeline", className="text-success mb-3")
            ),
            dbc.Col(
                dbc.Button("Download Trace", id="download-trace-logs-button", n_clicks=0, color="danger",style={'float': 'right', 'margin-left': '10px'})
            )
        ]),
        dbc.Table(table_content, bordered=True, dark=True, hover=True),
        ], className="bg-dark", style= {"width": "100vw" , "height": "92vh", 'overflow': 'auto', "padding-right": "20px", "padding-left": "20px"})