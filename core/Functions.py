import yaml
import csv
import os
import sys
import shutil
from datetime import datetime
from pathlib import Path
from dash import html, dcc
import dash_bootstrap_components as dbc
from core.Constants import *
from dash_iconify import DashIconify
from core.technique.master_record import MasterRecord
from core.technique.attack_library import HalberdAttackLibrary
from core.playbook.playbook import Playbook

def DisplayTechniqueInfo(technique_id):
    '''Generates Technique information from the MasterRecord.yml and displays it in the offcanvas on the attack page. The offcanvas is triggered by the About Technique button'''
    
    # load MasterRecord.yml file
    master_record = MasterRecord().data
    
    technique_info = master_record.get(technique_id, {})
    
    technique_details = []
    technique_details.append(html.H4(f"Technique: {technique_info.get('Name', 'N/A')}"))
    technique_details.append(html.P(f"ID: {technique_id}"))
    technique_details.append(html.H5(f"Attack Surface:"))
    technique_details.append(html.P(f"{technique_info.get('AttackSurface', 'N/A')}"))
    technique_details.append(html.H5("MITRE ATT&CK Reference:"))
    
    # add mitre technique information
    for mitre_info in technique_info.get('References', {}).get('MITRE', {}).values():
        ul_items = []
        ul_items.append(html.Li(f"Technique: {mitre_info.get('Technique', 'N/A')}"))
        ul_items.append(html.Li(f"Sub-technique: {mitre_info.get('SubTechnique', 'N/A')}"))
        ul_items.append(html.Li(f"Tactic: {', '.join(mitre_info.get('Tactic', ['N/A']))}"))
        mitre_url = mitre_info.get('URL', '#')
        if mitre_url in [None, "#"]:
            ul_items.append(html.Li(dcc.Link("More info", href="#")))
        else:
            ul_items.append(html.Li(dcc.Link("More info", href=mitre_url, target="_blank")))
        technique_details.append(html.Ul(ul_items))
    
    # display additional information under an accordion
    accordion_content = []

    # add technique description
    if technique_info.get('Description', None):
        accordion_content.append(html.H6("Technique Description:",  className="text-muted"))
        accordion_content.append(html.P(technique_info.get('Description', "N/A"), className="text-muted"))

    # add linked additional resources information
    linked_resources = technique_info.get('Resources', [])
    if linked_resources != [None]:
        accordion_content.append(html.H6("Additional Resources:",  className="text-muted"))
        for resource in linked_resources:
            accordion_content.append(html.Li(dcc.Link(f"{resource}", href=resource, target="_blank"), className="text-muted"))

    # add associated notes 
    technique_notes = technique_info.get('Notes','N/A')
    if technique_notes not in [['N/A'],[None]]:
        accordion_content.append(html.H6("Notes:",  className="text-muted"))
        for note in technique_notes:
            accordion_content.append(html.Li(note, className="text-muted"))
    
    # add accordion to modal body
    technique_details.append(
        dbc.Accordion(
            [
                dbc.AccordionItem(accordion_content, title = "Additional Information / Resources"),
            ],
            start_collapsed=True,
        )
    )

    # return technique details
    return technique_details


def TacticMapGenerator():
    '''Function to generate list of available tactics for each attack surface'''
    '''Function to run once at the start of application'''

    # load MasterRecord.yml file
    techniques_info = MasterRecord().data

    Entra_Id_Tactics = []
    Azure_Tactics = []
    AWS_Tactics = []
    M365_Tactics = []

    for t_id in techniques_info:
        if techniques_info[t_id]['References']['MITRE']:
            all_mitre_techniques = techniques_info[t_id]['References']['MITRE']

            for technique in all_mitre_techniques:
                if techniques_info[t_id]['AttackSurface'] == "EntraID":
                    Entra_Id_Tactics += all_mitre_techniques[technique]['Tactic']
                elif techniques_info[t_id]['AttackSurface'] == "Azure":
                    Azure_Tactics += all_mitre_techniques[technique]['Tactic']
                elif techniques_info[t_id]['AttackSurface'] == "AWS":
                    AWS_Tactics += all_mitre_techniques[technique]['Tactic']
                elif techniques_info[t_id]['AttackSurface'] == "M365":
                    M365_Tactics += all_mitre_techniques[technique]['Tactic']
    
    Entra_Id_Tactics = list(set(Entra_Id_Tactics))
    Azure_Tactics = list(set(Azure_Tactics))
    AWS_Tactics = list(set(AWS_Tactics))
    M365_Tactics = list(set(M365_Tactics))

    tactics_map = {"Entra_Id_Tactics" : Entra_Id_Tactics, "Azure_Tactics" : Azure_Tactics, "AWS_Tactics" : AWS_Tactics, "M365_Tactics" : M365_Tactics}

    with open(TACTICS_MAP_FILE, "w") as file:
        yaml.dump(tactics_map, file)
    
    print("[*] Tactic Map Updated")

    return Entra_Id_Tactics, Azure_Tactics, AWS_Tactics, M365_Tactics

def TechniqueMapGenerator():
    '''Function to generate list of available techniques for each attack surface'''
    '''Function to run once at the start of application'''

    # load MasterRecord.yml file
    techniques_info = MasterRecord().data
    
    Entra_Id_Technqiues = []
    Azure_Technqiues = []
    AWS_Technqiues = []
    M365_Technqiues = []

    for t_id in techniques_info:
        if techniques_info[t_id]['AttackSurface'] == "EntraID":
            Entra_Id_Technqiues.append(t_id)
        elif techniques_info[t_id]['AttackSurface'] == "Azure":
            Azure_Technqiues.append(t_id)
        elif techniques_info[t_id]['AttackSurface'] == "AWS":
            AWS_Technqiues.append(t_id)
        elif techniques_info[t_id]['AttackSurface'] == "M365":
            M365_Technqiues.append(t_id)
    
    Entra_Id_Technqiues = list(set(Entra_Id_Technqiues))
    Azure_Technqiues = list(set(Azure_Technqiues))
    AWS_Technqiues = list(set(AWS_Technqiues))
    M365_Technqiues = list(set(M365_Technqiues))

    technique_map = {"Entra_Id_Techniques" : Entra_Id_Technqiues, "Azure_Techniques" : Azure_Technqiues, "AWS_Techniques" : AWS_Technqiues, "M365_Techniques" : M365_Technqiues}

    with open(TECHNIQUES_MAP_FILE, "w") as file:
        yaml.dump(technique_map, file)

    print("[*] Technique Map Updated")
    return Entra_Id_Technqiues, Azure_Technqiues, AWS_Technqiues, M365_Technqiues


def TechniqueOptionsGenerator(tab, tactic):
    '''Function generates list of available techniques as dropdown options dynamically based on the attack surface(tab) and the tactic selected'''
    
    # load MasterRecord.yml file
    techniques_info = MasterRecord().data

    # load techniques map file
    with open(TECHNIQUES_MAP_FILE, "r") as technique_map_data:
        techniques_map = yaml.safe_load(technique_map_data)
    
    if tab == "tab-attack-Azure":
        attack_surface_techniques = techniques_map['Azure_Techniques']
    if tab == "tab-attack-AWS":
        attack_surface_techniques = techniques_map['AWS_Techniques']
    if tab == "tab-attack-M365":
        attack_surface_techniques = techniques_map['M365_Techniques']
    if tab == "tab-attack-EntraID":
        attack_surface_techniques = techniques_map['Entra_Id_Techniques']
        
    technique_options_list = []
    for technique in attack_surface_techniques:
        for mitre_technique in techniques_info[technique]['References']['MITRE']:
            if tactic in techniques_info[technique]['References']['MITRE'][mitre_technique]['Tactic']:
                technique_options_list.append(
                    {
                        "label": html.Div([techniques_info[technique]['Name']], style={"padding-left": "10px","padding-top": "5px", "padding-bottom": "5px", "font-size": 20}, className="bg-dark text-body"),
                        "value": technique,
                    }
                )

    technique_options_element = [
        html.H2(tactic),
        dcc.RadioItems(id = "attack-options-radio", options = technique_options_list, value = technique_options_list[0]["value"], labelStyle={"display": "flex", "align-items": "center"}),
        ]

    return technique_options_element

def TabContentGenerator(tab):

    # load all tactics information for each attack surface from the TacticsMap.yml file
    with open(TACTICS_MAP_FILE, "r") as tactics_file_data:
        tactics_map = yaml.safe_load(tactics_file_data)

    # from tab selected, create tactics dropdown list from the available tactics in the attack surface
    if tab == "tab-attack-M365":
        tactics_options = tactics_map['M365_Tactics']
    if tab == "tab-attack-EntraID":
        tactics_options = tactics_map['Entra_Id_Tactics']
    if tab == "tab-attack-Azure":
        tactics_options = tactics_map['Azure_Tactics']
    if tab == "tab-attack-AWS":
        tactics_options = tactics_map['AWS_Tactics']
    
    # create the dropdown element
    tactic_dropdown_option = []    
    for tactic in tactics_options:
        tactic_dropdown_option.append(
            {
                "label": html.Div([tactic], style={'font-size': 20}, className="text-dark"),
                "value": tactic,
            }
        )    

    tab_content_elements = []

    tab_content_elements.append(dcc.Dropdown(options = tactic_dropdown_option, value = tactic_dropdown_option[0]["value"], id='tactic-dropdown'))
    tab_content_elements.append(html.Br())

    # add element to display technique options under each tactic
    tab_content_elements.append(
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Div(id = "technique-options-div", className= "bg-dark"),
                ], width = 3, md=3, className="bg-dark border-end border-success"),
                dbc.Col([
                    html.Div(id= "attack-config-div",className='bg-dark divBorder d-grid col-6 mx-auto', style={'width' : '100%'}),
                ], width = 7,  className="mb-3"),
            ])  
        ], className="bg-dark p-3 border border-success rounded")
    )
    tab_content_elements.append(html.Br())
    tab_content_elements.append(html.Br())

    tab_content_elements.append(
        dbc.Row([
            dbc.Col(
                html.H4("Response")
            ),
            dbc.Col(
                dbc.Button([
                    DashIconify(icon="mdi:download"),
                ], id="download-technique-response-button", color="primary", style={'float': 'right', 'margin-left': '10px'}),
            )
        ])
    )
    # response loading element
    tab_content_elements.append(
        dcc.Loading(
            id="attack-output-loading",
            type="default",
            children=html.Div(id= "execution-output-div",style={"height":"40vh", "overflowY": "auto", "border":"1px solid #ccc", "padding-right": "10px", "padding-left": "10px", "padding-top": "10px", "padding-bottom": "10px"}, className = "rounded")
        )
    )

    # final tab div to return
    tab_content = html.Div(
        tab_content_elements,
        style={"height":"87vh", "padding-right": "20px", "padding-left": "20px", "padding-top": "20px", "padding-bottom": "20px"}, 
        className="bg-dark"
    )

    return tab_content

def WriteAppLog(action, result = "success"):
    log_file = APP_LOG_FILE
    f = open(log_file,"a")

    fields = ["date_time", "action","result"]
    log_input = {"date_time": str(datetime.today()), "action":action, "result":result}

    write_log = csv.DictWriter(f, fieldnames= fields)
    write_log.writerow(log_input)

    return True
    
def ReadAppLogger():
    log_file = APP_LOG_FILE
    f = open(log_file,"r")
    return csv.DictReader(f)

def ReadTraceLog():
    log_file = TRACE_LOG_FILE
    f = open(log_file,"r")
    return csv.DictReader(f)

def CheckAzureCLIInstall():
    '''Function checks for installation of Azure cli on host'''
    
    if sys.platform.startswith('win'):
        # search in PATH
        az_cli_path = shutil.which("az")
        if az_cli_path:
            return az_cli_path
        
        # if not found in PATH, check in common installation paths on Windows
        common_win_paths = [
            r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin",
            r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin",
        ]
        for path in common_win_paths:
            az_cli_path = os.path.join(path, "az.cmd")
            if os.path.exists(az_cli_path):
                return az_cli_path
            
    else:
        # for non-windows systems, check if 'az' is in PATH
        if shutil.which("az"):
            return "az"
    
    # if az installation not found on host,return None
    return None

def InitializationCheck():
    # Check for local folder
    if Path(APP_LOCAL_DIR).exists():
        pass
    else:
        os.makedirs(APP_LOCAL_DIR)

    # Check for application log file
    if Path(APP_LOG_FILE).exists():
        pass
    else:
        f = open(APP_LOG_FILE,"a")

        fields = ["date_time", "action","result"]
        log_input = {"date_time": "date_time", "action":"action", "result":"result"}

        write_log = csv.DictWriter(f, fieldnames= fields)
        write_log.writerow(log_input)
        print("[*] Application log file created")

    # Check for trace log file
    if Path(TRACE_LOG_FILE).exists():
        pass
    else:
        f = open(TRACE_LOG_FILE,"a")

        fields = ["date_time", "technique", "tactic","attack_surface","result"]
        log_input = {"date_time":"date_time", "technique":"technique", "tactic":"tactic","attack_surface":"attack_surface", "result":"result"}

        write_log = csv.DictWriter(f, fieldnames= fields)
        write_log.writerow(log_input)
        print("[*] Trace log file created")

    # check for msft tokens file
    if Path(MSFT_TOKENS_FILE).exists():
        pass
    else:
        all_tokens_data = {'AllTokens':[]}

        with open(MSFT_TOKENS_FILE, 'w') as file:
            yaml.dump(all_tokens_data, file)

    # check for automator folder
    if Path(AUTOMATOR_DIR).exists():
        # check for automtor/Playbooks folder
        if Path(AUTOMATOR_PLAYBOOKS_DIR).exists():
            pass
        else:
            os.makedirs(AUTOMATOR_PLAYBOOKS_DIR)
            print("[*] Automator dir created")
        
        # check for automator/Outputs folder
        if Path(AUTOMATOR_OUTPUT_DIR).exists():
            pass
        else:
            os.makedirs(AUTOMATOR_OUTPUT_DIR)
            print("[*] Automator outputs dir created")
        
        # check for automator/Exports folder
        if Path(AUTOMATOR_EXPORTS_DIR).exists():
            pass
        else:
            os.makedirs(AUTOMATOR_EXPORTS_DIR)
            print("[*] Automator exports dir created")

        # check for automator/Schedules.yml file
        if Path(AUTOMATOR_SCHEDULES_FILE).exists():
            pass
        else:
            # create Schedules.yml config file
            with open(AUTOMATOR_SCHEDULES_FILE, 'w') as file:
                pass
            print("[*] Schedules config file created")
            
    else:
        # create all automator dirs and files
        os.makedirs(AUTOMATOR_DIR)
        os.makedirs(AUTOMATOR_PLAYBOOKS_DIR)
        os.makedirs(AUTOMATOR_OUTPUT_DIR)
        with open(AUTOMATOR_SCHEDULES_FILE, 'w') as file:
            pass
        print("[*] Automator files created")

    # check az cli installation
    if CheckAzureCLIInstall():
        pass
    else:
        # print warning on terminal
        warning = '''
        ⚠️  WARNING: Azure CLI (az) not found! ⚠️
        --------------------------------------------
        The Azure CLI is required to run the Azure modules but was not found on the system.
        Please ensure that:
        1. Azure CLI is installed on the system.
        2. The installation directory is added to your system's PATH.
        3. You have restarted your terminal or IDE after installation.

        For installation instructions, visit:
        https://learn.microsoft.com/en-us/cli/azure/install-azure-cli

        After installation, you may need to restart your terminal or add the Azure CLI 
        installation directory to your PATH manually.
        '''
        print(warning)


def PlaybookCreateCSVReport(report_file_name, time_stamp, module, result):
    '''Function to create and write to execution summary report in CSV format'''

    # define headers
    headers = ["Time_Stamp", "Module", "Result"]

    if Path(f"{AUTOMATOR_DIR}/{report_file_name}").exists():
        pass
    else:
        # create new report file with headers
        f = open(report_file_name,"a")
        report_input = {"Time_Stamp":"Time_Stamp", "Module":"Module", "Result":"Result"}
        write_log = csv.DictWriter(f, fieldnames= headers)
        write_log.writerow(report_input)

    # write execution information to report
    report_input = {"Time_Stamp": time_stamp, "Module": module, "Result": result}
    write_log = csv.DictWriter(f, fieldnames= headers)
    write_log.writerow(report_input)

def AddNewSchedule(schedule_name, playbook_id, start_date, end_date, execution_time, repeat, repeat_frequency):
    # automator file
    with open(AUTOMATOR_SCHEDULES_FILE, "r") as schedule_data:
        schedules = yaml.safe_load(schedule_data)

    # if no schedule present, initialize dictionary
    if schedules == None:
        schedules = {}

    # input handling
    if schedule_name in [None, ""]:
        sched_create_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        schedule_name = f"schedule-{sched_create_time}"

    schedules[schedule_name] = {"Playbook_Id" : playbook_id, "Start_Date" : start_date, "End_Date" : end_date, "Execution_Time" : execution_time, "Repeat" : str(repeat), "Repeat_Frequency" : repeat_frequency}
    # update schedules file
    with open(AUTOMATOR_SCHEDULES_FILE, "w") as file:
        yaml.dump(schedules, file)


def GetAllPlaybooks():
    # list all playbooks
    all_playbooks = []
    try:
        # check playbooks directory
        dir_contents = os.listdir(AUTOMATOR_PLAYBOOKS_DIR)
        for content in dir_contents:
            if os.path.isfile(os.path.join(AUTOMATOR_PLAYBOOKS_DIR, content)) and content.lower().endswith(".yml"):
                # if content is a yml file
                all_playbooks.append(content)

        return all_playbooks
    
    except FileNotFoundError:
        return "File not found"
    except PermissionError:
        return "Permissions error"
    except:
        return "Error"

def DisplayPlaybookInfo(selected_pb):
    for pb in GetAllPlaybooks():
        playbook = Playbook(pb)
        if  playbook.name == selected_pb:
            break
    display_elements = []

    # display playbook name
    display_elements.append(html.H4(f"Name : {playbook.name}"))
    display_elements.append(html.Br())

    # display playbook description
    display_elements.append(html.H5("Description : "))
    display_elements.append(html.P(playbook.description))

    # display playbook step count
    display_elements.append(html.H5(f"Steps Count : {playbook.steps}"))
    display_elements.append(html.P(""))

    # display playbook author
    display_elements.append(html.H5("Plabook Author : "))
    display_elements.append(html.P(playbook.author))

    # display playbook creation date
    display_elements.append(html.H5("Plabook Creation Date : "))
    display_elements.append(html.P(playbook.creation_date))

    # display playbook references
    display_elements.append(html.H5("Plabook References : "))
    if playbook.references: 
        if type(playbook.references) == list:
            for ref in playbook.references:
                display_elements.append(html.Li(dcc.Link(ref, href=ref, target='_blank')))
        else:
            display_elements.append(html.Li(dcc.Link(playbook.references, href=playbook.references, target='_blank')))
    else:
        display_elements.append(html.P("N/A"))

    return display_elements 

def ParseTechniqueResponse(technique_response):
    '''Function to parse the technique execution response and display it structured'''
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

def LogEventOnTrigger(tactic, t_id):
    '''Function to log event on execution'''
    library = HalberdAttackLibrary()
    technique = library.get_technique(t_id)
    technique_name = technique.name
    attack_surface = technique.attack_surface

    f = open(TRACE_LOG_FILE,"a")

    fields = ["date_time", "technique", "tactic","attack_surface","result"]
    log_input = {"date_time":str(datetime.today()), "technique":technique_name, "tactic":tactic,"attack_surface":attack_surface, "result":"Executed"}

    write_log = csv.DictWriter(f, fieldnames= fields)
    write_log.writerow(log_input)

    return True