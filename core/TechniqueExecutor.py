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
            output_div_elements.append(html.Div(str(item), style={"overflowY": "scroll", "border":"1px solid #ccc"}))
            output_div_elements.append(html.Br())

        return html.Div(output_div_elements)

    elif type(response) == dict:
        if response == {}:
            return html.H4("No results returned", style ={"textAlign": "center", "padding": "5px"})
        
        output_div_elements = []
        for item in response:
            output_div_elements.append(
                html.Div([
                    html.Div(item),
                    html.Div(str(response[item])),
                ], style={"overflowY": "scroll", "border":"1px solid #ccc"})
            )
            output_div_elements.append(html.Br())

        return html.Div(output_div_elements)

    else:
        return str(response)



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
