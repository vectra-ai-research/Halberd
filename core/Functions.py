import yaml
import csv
from datetime import datetime
from pathlib import Path
import os
from dash import html, dcc
import dash_bootstrap_components as dbc
from core.Constants import *
from core.Automator import GetAllPlaybooks, Playbook

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

    # add element to display output of executed technique
    tab_content_elements.append(html.H4("Response"))
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
        if Path(AUTOMATOR_SCHEDULES_DIR).exists():
            pass
        else:
            # create Schedules.yml config file
            with open(AUTOMATOR_SCHEDULES_DIR, 'w') as file:
                pass
            print("[*] Schedules config file created")
            
    else:
        # create all automator dirs and files
        os.makedirs(AUTOMATOR_DIR)
        os.makedirs(AUTOMATOR_PLAYBOOKS_DIR)
        os.makedirs(AUTOMATOR_OUTPUT_DIR)
        with open(AUTOMATOR_SCHEDULES_DIR, 'w') as file:
            pass
        print("[*] Automator files created")

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