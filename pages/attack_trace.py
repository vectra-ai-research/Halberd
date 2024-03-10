from dash import html, dcc
import dash_bootstrap_components as dbc
from csv import DictReader 

def GenerateAttackTraceView():

    # Load trace log file
    log_file = "./Local/Trace_Log.csv"
    f = open(log_file,"r")
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
        html.H3("Attack Trace - Event Timeline", style ={"textAlign": "center", "padding": "5px"}),
        dbc.Button("Download Trace", id="download-trace-logs-button", n_clicks=0, color="danger",style={'float': 'right', 'margin-left': '10px'}),
        dcc.Download(id="download-trace-logs"),
        dbc.Table(table_content, bordered=True, dark=True, hover=True),
        ], className="bg-dark", style= {"width": "100vw" , "height": "92vh", 'overflow': 'auto'})