'''
Page Navigation url : app/attack-trace
Page Description : Page displays a table view of executed modules and allows exporting the data in a csv format. The view is generated from local/app.log which is created locally on the users host.  
'''

import json
import dash_bootstrap_components as dbc
from dash import html, dash_table
import pandas as pd
from core.Constants import APP_LOG_FILE

# Function to parse log file
def parse_log_file(file_path):
    """Function to parse the app log file"""
    events = []
    with open(file_path, 'r') as file:
        next(file)  # Skip the header line
        for line in file:
            if "Technique Execution" in line:
                parts = line.split(" - INFO - Technique Execution ")
                timestamp = parts[0].split(',')[0]
                event_data = json.loads(parts[1])
                event_data['log_timestamp'] = timestamp
                events.append(event_data)
    return events

# Group events by event_id
def group_events(events):
    """Function to group multiple logs linked to an event"""
    grouped = {}
    for event in events:
        event_id = event['event_id']
        if event_id not in grouped:
            grouped[event_id] = []
        grouped[event_id].append(event)
    return grouped

# Create summary of events
def create_summary(grouped_events):
    """Function to create summary of events from multiple log lines"""
    summary = []
    for event_id, events in grouped_events.items():
        start_event = next((e for e in events if e['status'] == 'started'), None)
        end_event = next((e for e in events if e['status'] in ['completed', 'failed']), None)
        
        if start_event and end_event:
            summary.append({
                'Technique': start_event.get('technique', 'N/A'),
                'Source': start_event.get('source', 'Unknown'),
                'Start Time': start_event['log_timestamp'],
                'End Time': end_event['log_timestamp'],
                'Status': end_event['status'],
                'Result': end_event.get('result', 'N/A'),
                'Target': end_event.get('target', 'N/A'),
                'Tactic': start_event.get('tactic', 'N/A'),
                'Event ID': event_id
            })
    
    return summary

def generate_attack_trace_view():
    """Function to generate the attack trace table view"""

    # Parse log file and create summary
    events = parse_log_file(APP_LOG_FILE)
    grouped_events = group_events(events)
    summary = create_summary(grouped_events)

    # Create DataFrame
    df = pd.DataFrame(summary)

    # Return app layout
    return html.Div([
        dbc.Row([
            dbc.Col(
                html.H2("Attack Trace - Event Timeline", className="text-success mb-3")
            ),
            dbc.Col([
                dbc.Button("Download Trace", id="download-trace-logs-button", n_clicks=0, color="danger",style={'float': 'right', 'margin-left': '10px'}),
                dbc.Button("Download Report", id="download-trace-report-button", n_clicks=0, color="success",style={'float': 'right', 'margin-left': '10px'})
        ])
        ]),
        dash_table.DataTable(
            id='trace-table',
            columns=[{"name": i, "id": i} for i in df.columns],
            data=df.to_dict('records'),
            style_table={
                'overflowX': 'auto',
                'backgroundColor': '#2F4F4F'
            },
            style_cell={
                'textAlign': 'left',
                'backgroundColor': '#2F4F4F',
                'color': 'white',
                'border': '1px solid #3a3a3a'
            },
            style_header={
                'backgroundColor': '#000000',
                'fontWeight': 'bold',
                'border': '1px solid #3a3a3a'
            },
            style_data_conditional=[
                {
                    'if': {'row_index': 'odd'},
                    'backgroundColor': '#3D5C5C'
                }
            ],
            sort_action='native',
            filter_action = 'native',
            page_size=20
        ),
    ], className="bg-dark", style= {"width": "100vw" , "height": "92vh", 'overflow': 'auto', "padding-right": "20px", "padding-left": "20px"})
