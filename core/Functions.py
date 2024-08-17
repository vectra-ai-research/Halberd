import yaml
import re
import csv
import importlib
import base64
import os
import sys
import shutil
from datetime import datetime
from pathlib import Path
from dash import html, dcc
import dash_bootstrap_components as dbc
from core.Constants import *
from dash_iconify import DashIconify
import subprocess

class MasterRecord:
    def __init__(self):
        # load the MasterRecord.yml file
        with open(MASTER_RECORD_FILE, 'r') as file:
            master_record = yaml.safe_load(file)
        
        self.data = master_record

        self.entra_id = {}
        self.m365 = {}
        self.aws = {}
        self.azure = {}

        techniques_list = []
        entra_id_techniques_list = []
        m365_techniques_list = []
        aws_techniques_list = []
        azure_techniques_list = []

        for technique in master_record:
            techniques_list.append(technique)

            if str(technique).startswith("EntraID"):
                self.entra_id[technique] = master_record[technique]
                entra_id_techniques_list.append(technique)
            elif str(technique).startswith("M365"):
                self.m365[technique] = master_record[technique]
                m365_techniques_list.append(technique)
            elif str(technique).startswith("AWS"):
                self.aws[technique] = master_record[technique]
                aws_techniques_list.append(technique)
            elif str(technique).startswith("Azure"):
                self.azure[technique] = master_record[technique]
                azure_techniques_list.append(technique)

        self.list_all_techniques = techniques_list
        self.list_m365_techniques = m365_techniques_list
        self.list_entraid_techniques = entra_id_techniques_list
        self.list_aws_techniques = aws_techniques_list
        self.list_azure_techniques = azure_techniques_list

        self.count_all_techniques = len(techniques_list)
        self.count_m365_techniques = len(m365_techniques_list)
        self.count_entraid_techniques = len(entra_id_techniques_list)
        self.count_aws_techniques = len(aws_techniques_list)
        self.count_azure_techniques = len(azure_techniques_list)

class Playbook:
    def __init__(self, pb_file_name):
        pb_config_file = AUTOMATOR_PLAYBOOKS_DIR + "/" + pb_file_name
        with open(pb_config_file, "r") as pb_config_data:
            pb_config = yaml.safe_load(pb_config_data)

        self.file = pb_config_file
        self.name = pb_config["PB_Name"]
        self.description = pb_config["PB_Description"]
        self.author = pb_config["PB_Author"]
        self.creation_date = pb_config["PB_Creation_Date"]
        self.references = pb_config["PB_References"]
        self.sequence = pb_config["PB_Sequence"]

    def AddPlaybookStep(self, module, params = None, wait = 30):
        # adds a new step to playbook. New step is added as the last step of the sequence
        pb_sequence = self.sequence

        if list(pb_sequence.keys()) == []:
            # for a newly created playbook, step count will be zero / an empty list
            pb_steps_count = 0
        else:
            # get step count for an existing playbook
            pb_steps_count = max(list(pb_sequence.keys()))
            
        # add new step to playbook
        pb_sequence[pb_steps_count+1] = {"Module": module, "Params": params, "Wait": wait}
    
    def SavePlaybook(self):
        # saves latest changes to Playbook file 
        with open(self.file, "r") as pb_file:
            pb_config = yaml.safe_load(pb_file)

        pb_config["PB_Sequence"] = self.sequence
        
        # update playbook config file
        with open(self.file, "w") as pb_file:
            yaml.dump(pb_config, pb_file)

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

def ExecutePlaybook(playbook_name):
    
    # import techniques info from MasterRecord.yml
    techniques_info = MasterRecord().data

    # automator file
    for pb in GetAllPlaybooks():
        pb_config = Playbook(pb)
        if  pb_config.name == playbook_name:
            playbook_attack_config = pb_config.sequence

    # create automation run folder
    execution_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    execution_folder_name = f"{playbook_name}_{execution_time}"
    os.makedirs(f"{AUTOMATOR_OUTPUT_DIR}/{execution_folder_name}")

    # store current execution config
    with open(f"{AUTOMATOR_OUTPUT_DIR}/{execution_folder_name}/Execution_Config.yml", 'w') as file:
        # Write the YAML data to the file
        yaml.dump(playbook_attack_config, file, default_flow_style=False)

    execution_report_file = f"{AUTOMATOR_OUTPUT_DIR}/{execution_folder_name}/Report.csv"

    # execute attack sequence
    for step in playbook_attack_config:
        module_tid = playbook_attack_config[step]["Module"]
        '''technique input'''
        technique_input = playbook_attack_config[step]["Params"]

        '''technique execution'''
        execution_path = techniques_info[module_tid]['ExecutionPath']

        exec_module_path = re.findall(r'[^\/\.]+', execution_path)
        exec_module = importlib.import_module(f"Techniques.{exec_module_path[0]}.{exec_module_path[1]}")
        TechniqueMainFunction = getattr(exec_module, "TechniqueMain")

        # module execution start time
        execution_start_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        if technique_input == None:
            technique_response = TechniqueMainFunction()
        else:
            technique_response = TechniqueMainFunction(*technique_input)

        '''technique output'''
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

        # save output
        module_output_file = f"{AUTOMATOR_OUTPUT_DIR}/{execution_folder_name}/Result_{module_tid}.txt"
        with open(module_output_file, 'w') as file:
            # write the data to the file
            file.write(str(response))

        # create summary report & store responses
        try:
            if success == True:
                PlaybookCreateCSVReport(execution_report_file, execution_start_time, module_tid, "success")
            else:
                PlaybookCreateCSVReport(execution_report_file, execution_start_time, module_tid, "failed")
        except:
            PlaybookCreateCSVReport(execution_report_file, execution_start_time, module_tid, "failed")

def AddNewSchedule(schedule_name, automation_id, start_date, end_date, execution_time, repeat, repeat_frequency):
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

    schedules[schedule_name] = {"Playbook_Id" : automation_id, "Start_Date" : start_date, "End_Date" : end_date, "Execution_Time" : execution_time, "Repeat" : str(repeat), "Repeat_Frequency" : repeat_frequency}
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

def ImportPlaybook(file_content, filename):
    # function to import external Halberd playbooks 
    if file_content is not None:
        # base64 decoding file contents
        content_type, content_string = file_content.split(',')
        decoded_content = base64.b64decode(content_string)
        
        # save playbook to playbooks directory
        playbook_filepath = os.path.join(AUTOMATOR_PLAYBOOKS_DIR, filename)
        with open(playbook_filepath, 'wb') as f:
            f.write(decoded_content)
        
        return None

def CreateNewPlaybook(name, description = "N/A", author = "N/A", references = "N/A"):
    playbook_config = {}
    creation_date = datetime.today().strftime('%m-%d-%Y')
    playbook_config["PB_Author"] = author
    playbook_config["PB_Creation_Date"] = creation_date
    playbook_config["PB_Description"] = str(description)
    playbook_config["PB_Name"] = str(name)
    playbook_config["PB_References"] = references
    
    # initialize playbook with empty sequence
    playbook_config["PB_Sequence"] = {}

    # new playbook file
    pb_file = f"{AUTOMATOR_PLAYBOOKS_DIR}/{name}.yml"

    # update playbook file
    with open(pb_file, "w") as file:
        yaml.dump(playbook_config, file)

def DisplayPlaybookInfo(selected_pb):
    for pb in GetAllPlaybooks():
        pb_config = Playbook(pb)
        if  pb_config.name == selected_pb:
            break
    display_elements = []

    # display playbook name
    display_elements.append(html.H4(f"Name : {pb_config.name}"))
    display_elements.append(html.Br())

    # display playbook description
    display_elements.append(html.H5("Description : "))
    display_elements.append(html.P(pb_config.description))

    # display playbook step count
    if pb_config.sequence == {}:
        display_elements.append(html.H5("Steps Count : "))
        display_elements.append(html.P("0"))
    else:
        display_elements.append(html.H5("Plabook Steps Count : "))
        display_elements.append(html.P(max(pb_config.sequence.keys())))

    # display playbook author
    display_elements.append(html.H5("Plabook Author : "))
    display_elements.append(html.P(pb_config.author))

    # display playbook creation date
    display_elements.append(html.H5("Plabook Creation Date : "))
    display_elements.append(html.P(pb_config.creation_date))

    # display playbook references
    display_elements.append(html.H5("Plabook References : "))
    if pb_config.references: 
        if type(pb_config.references) == list:
            for ref in pb_config.references:
                display_elements.append(html.Li(dcc.Link(ref, href=ref, target='_blank')))
        else:
            display_elements.append(html.Li(dcc.Link(pb_config.references, href=pb_config.references, target='_blank')))
    else:
        display_elements.append(html.P("N/A"))

    return display_elements 