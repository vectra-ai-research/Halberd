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
import dash_bootstrap_components as dbc

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
def TechniqueOutput(t_id, technique_input, bool_flag = None, file_content = None):

    # execute technique
    execution_path = techniques_info[t_id]['ExecutionPath']

    exec_module_path = re.findall(r'[^\/\.]+', execution_path)
    exec_module = importlib.import_module(f"Techniques.{exec_module_path[0]}.{exec_module_path[1]}")
    print(f"Executing {exec_module}")
    TechniqueMainFunction = getattr(exec_module, "TechniqueMain")
    
    # check if the technique input contains boolean flags / file content
    if bool_flag and file_content:
        technique_response = TechniqueMainFunction(*technique_input, bool_flag, file_content)
    elif bool_flag:
        technique_response = TechniqueMainFunction(*technique_input, bool_flag)
    elif file_content:
        technique_response = TechniqueMainFunction(*technique_input, file_content)
    else:
        technique_response = TechniqueMainFunction(*technique_input)

    # check if technique output is in the expected tuple format (success, raw_response, pretty_response)
    if isinstance(technique_response, tuple) and len(technique_response) == 3:
        success, raw_response, pretty_response = technique_response
        # parse output
        if pretty_response != None:
            response = pretty_response
        else:
            response = raw_response
    else:
        response = technique_response

    # initialize the response div elements list
    response_div_elements = []

    # display notification based on technique result
    try:
        if success == True:
            response_div_elements.append(
                dbc.Toast(
                    children = "Success",
                    id="output-notification",
                    header="Technique Result",
                    is_open=True,
                    dismissable=True,
                    duration=5000,
                    color="success",
                    style={"position": "fixed", "top": 166, "right": 10, "width": 350},
                )
            )
        else:
            response_div_elements.append(
                dbc.Toast(
                    children = "Failed",
                    id="output-notification",
                    header="Technique Result",
                    is_open=True,
                    dismissable=True,
                    duration=5000,
                    color="danger",
                    style={"position": "fixed", "top": 168, "right": 10, "width": 350},
                )
            )
    except:
        pass

    '''Format parsed response based on response data type (dict / list / str)'''
    if isinstance(response,list):
        # if the response is a null then return message
        if response == []:
            return html.H4("No results returned", style ={"textAlign": "center", "padding": "5px"})
        
        for item in response:
            response_div_elements.append(html.Div(str(item), style={"overflowY": "auto", "border":"1px solid #ccc"}))
            response_div_elements.append(html.Br())

        return html.Div(response_div_elements)

    elif isinstance(response,dict):
        # if the response is a null then return message
        if response == {}:
            return html.H4("No results returned", style ={"textAlign": "center", "padding": "5px"})
        
        for item in response:
            response_div_elements.append(html.H3(f"{item}"))

            if isinstance(response[item], dict):
                sub_response_div_elements = []
                for sub_item in response[item]:
                    sub_response_div_elements.append(
                        f"{sub_item} : {response[item][sub_item]}"
                    )
                    sub_response_div_elements.append(html.Br())
                    sub_response_div_elements.append(html.Br())
                
                response_div_elements.append(
                    html.Div([
                        html.Div(sub_response_div_elements),
                    ], style={"overflowY": "auto", "border":"1px solid #ccc"})
                )
                response_div_elements.append(html.Br())

            else:
                response_div_elements.append(
                    html.Div([
                        html.Div(str(response[item])),
                    ], style={"overflowY": "auto", "border":"1px solid #ccc"})
                )
                response_div_elements.append(html.Br())

        return html.Div(response_div_elements)

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
