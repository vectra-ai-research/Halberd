import yaml
from core.Constants import *

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