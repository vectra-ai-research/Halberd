'''
Name : TechniqueExecutor.py
Description : Loads techniques functions to display technique config, logs event on technique execution and parses technique response to display standardized output in 'execution-output-div'.
'''
import yaml
import re
import importlib
import csv
from datetime import datetime
from dash import html

master_record_file = "./Techniques/MasterRecord.yml"
with open(master_record_file, "r") as master_record_data:
    techniques_info = yaml.safe_load(master_record_data)


def TechniqueInputs(t_id):
    execution_path = techniques_info[t_id]['ExecutionPath']

    exec_module_path = re.findall(r'[^\/\.]+', execution_path)
    exec_module = importlib.import_module(f"Techniques.{exec_module_path[0]}.{exec_module_path[1]}")
    TechniqueExecutionFunction = getattr(exec_module, "TechniqueInputSrc")

    return TechniqueExecutionFunction()

# function to parse technique output and return standardized output
def TechniqueOutput(t_id, technique_input, file_content = None):

    execution_path = techniques_info[t_id]['ExecutionPath']

    exec_module_path = re.findall(r'[^\/\.]+', execution_path)
    exec_module = importlib.import_module(f"Techniques.{exec_module_path[0]}.{exec_module_path[1]}")
    print(f"Executing {exec_module}")
    TechniqueMainFunction = getattr(exec_module, "TechniqueMain")

    if file_content != None:
        response = TechniqueMainFunction(*technique_input, file_content)
    else:
        response = TechniqueMainFunction(*technique_input)

    '''Automatically cleanup output'''
    if type(response) == list:
        if response == []:
            return html.H4("No results returned", style ={"textAlign": "center", "padding": "5px"})
        
        output_div_elements = []
        for item in response:
            output_div_elements.append(html.Div(str(item), style={"overflowY": "auto", "border":"1px solid #ccc"}))
            output_div_elements.append(html.Br())

        return html.Div(output_div_elements)

    elif type(response) == dict:
        if response == {}:
            return html.H4("No results returned", style ={"textAlign": "center", "padding": "5px"})
        
        output_div_elements = []
        for item in response:
            output_div_elements.append(html.H3(item))
            output_div_elements.append(
                html.Div([
                    html.Div(str(response[item])),
                ], style={"overflowY": "auto", "border":"1px solid #ccc"})
            )
            output_div_elements.append(html.Br())

        return html.Div(output_div_elements)

    else:
        return str(response)

# function to log event on execution
def LogEventOnTrigger(tactic, t_id):
    technique_name = techniques_info[t_id]['Name']
    attack_surface = techniques_info[t_id]['AttackSurface']

    log_file = "./local/Trace_Log.csv"
    f = open(log_file,"a")

    fields = ["date_time", "technique", "tactic","attack_surface","result"]
    log_input = {"date_time":str(datetime.today()), "technique":technique_name, "tactic":tactic,"attack_surface":attack_surface, "result":"Executed"}

    write_log = csv.DictWriter(f, fieldnames= fields)
    write_log.writerow(log_input)

    return True
