'''
Page Navigation URL : app/schedules
Page Description : Displays currently configured playbook execution schedules
'''

from dash import html
import dash_bootstrap_components as dbc
import yaml
from core.Constants import AUTOMATOR_SCHEDULES_FILE

def GenerateAutomatorSchedulesView():

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
        html.H3("Automator Schedules", style ={"textAlign": "center", "padding": "5px"}),
        dbc.Table(table_content, bordered=True, dark=True, hover=True),
        ], className="bg-dark", style= {"width": "100vw" , "height": "92vh", 'overflow': 'auto'})