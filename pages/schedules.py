'''
Page Navigation URL : app/schedules
Page Description : Displays currently configured playbook execution schedules
'''

from dash import html
import dash_bootstrap_components as dbc
import yaml
from dash_iconify import DashIconify
from core.Constants import AUTOMATOR_SCHEDULES_FILE

def generate_automator_schedules_view():

    with open(AUTOMATOR_SCHEDULES_FILE, "r") as schedule_data:
        schedules = yaml.safe_load(schedule_data)

    # set table headers
    table_header = [
        html.Thead(html.Tr([html.Th("Schedule ID"), html.Th("Playbook Name"), html.Th("Start Date"), html.Th("End Date"), html.Th("Repeat"), html.Th("Repeat Frequency"), html.Th("Time")]))
    ]

    # add table entries
    table_entries = []
    for schedule in schedules:
        table_entries.append(
            html.Tr([html.Td(schedule), html.Td(schedules[schedule]['Playbook_Id']), html.Td(schedules[schedule]['Start_Date']), html.Td(schedules[schedule]['End_Date']), html.Td(schedules[schedule]['Repeat']), html.Td(schedules[schedule]['Repeat_Frequency']), html.Td(schedules[schedule]['Execution_Time'])])
        )

    table_body = [html.Tbody(table_entries)]
    table_content = table_header + table_body

    # Generate attack trace page layout
    return html.Div([
        html.H2(
            [
                "Automator Schedules",
                html.A(DashIconify(icon="mdi:help-circle-outline", width=18, height=18), href="https://github.com/vectra-ai-research/Halberd/wiki/UI-&-Navigation", target="_blank")
            ], className="halberd-brand mb-3"
        ),
        dbc.Table(table_content, bordered=True, dark=True, hover=True),
        ], 
        className="bg-halberd-dark", 
        style= {
            "width": "100vw" , 
            "height": "92vh", 
            "overflow": "auto",
            "padding-right": "20px", 
            "padding-left": "20px",
            }
        )