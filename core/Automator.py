import yaml
import re
import importlib
from datetime import datetime
import os
import csv
from pathlib import Path
import time
import base64
import schedule

playbooks_dir = "./automator/Playbooks"

def write_csv_report(report_file_name, time_stamp, module, result):
    '''Function to create and write to execution summary report in CSV format'''

    # define headers
    headers = ["Time_Stamp", "Module", "Result"]

    if Path(f"./automator/{report_file_name}").exists():
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
    master_record_file = "./Techniques/MasterRecord.yml"
    with open(master_record_file, "r") as master_record_data:
        techniques_info = yaml.safe_load(master_record_data)

    # automator file
    for pb in GetAllPlaybooks():
        pb_config = Playbook(pb)
        if  pb_config.name == playbook_name:
            playbook_attack_config = pb_config.sequence

    # create automation run folder
    execution_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    execution_folder_name = f"{playbook_name}_{execution_time}"
    os.makedirs(f"./automator/Outputs/{execution_folder_name}")

    # store current execution config
    with open(f"./automator/Outputs/{execution_folder_name}/Execution_Config.yml", 'w') as file:
        # Write the YAML data to the file
        yaml.dump(playbook_attack_config, file, default_flow_style=False)

    execution_report_file = f"./automator/Outputs/{execution_folder_name}/Report.csv"

    # execute attack sequence
    for step in playbook_attack_config:
        module_tid = playbook_attack_config[step]["Module"]
        print(module_tid)
        print(playbook_attack_config[step])
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
        module_output_file = f"./automator/Outputs/{execution_folder_name}/Result_{module_tid}.txt"
        with open(module_output_file, 'w') as file:
            # Write the data to the file
            file.write(str(response))

        # create summary report & store responses
        try:
            if success == True:
                write_csv_report(execution_report_file, execution_start_time, module_tid, "success")
            else:
                write_csv_report(execution_report_file, execution_start_time, module_tid, "failed")
        except:
            write_csv_report(execution_report_file, execution_start_time, module_tid, "failed")

def AddNewSchedule(schedule_name, automation_id, start_date, end_date, execution_time, repeat, repeat_frequency):
    # automator file
    schedules_file = "./automator/Schedules.yml"
    with open(schedules_file, "r") as schedule_data:
        schedules = yaml.safe_load(schedule_data)

    # input handling
    if schedule_name in [None, ""]:
        schedule_name = time()

    schedules[schedule_name] = {"Playbook_Id" : automation_id, "Start_Date" : start_date, "End_Date" : end_date, "Execution_Time" : execution_time, "Repeat" : str(repeat), "Repeat_Frequency" : repeat_frequency}
    # update schedules file
    with open(schedules_file, "w") as file:
        yaml.dump(schedules, file)


def GetAllPlaybooks(playbooks_dir = "./automator/Playbooks"):
    # list all playbooks
    all_playbooks = []
    try:
        dir_contents = os.listdir(playbooks_dir)
        for content in dir_contents:
            if os.path.isfile(os.path.join(playbooks_dir, content)) and content.lower().endswith(".yml"):
                # if content is a yml file
                all_playbooks.append(content)

        return all_playbooks
    
    except FileNotFoundError:
        return "File not found"
    except PermissionError:
        return "Permissions error"
    except:
        return "Error"

def ReadPlaybookConfig(pb_file_name):
    # parse playbook configuration
    pb_config_file = "./automator/Playbooks/" + pb_file_name
    with open(pb_config_file, "r") as pb_config_data:
        pb_config = yaml.safe_load(pb_config_data)
    print(pb_config)

class Playbook:
    def __init__(self, pb_file_name):
        pb_config_file = "./automator/Playbooks/" + pb_file_name
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

        pb_steps_count = max(list(pb_sequence.keys()))

        pb_sequence[pb_steps_count+1] = {"Module": module, "Params": params, "Wait": wait}
    
    def SavePlaybook(self):
        # saves latest changes to Playbook file 
        with open(self.file, "r") as pb_file:
            pb_config = yaml.safe_load(pb_file)

        pb_config["PB_Sequence"] = self.sequence
        
        # update playbook config file
        with open(self.file, "w") as pb_file:
            yaml.dump(pb_config, pb_file)

def ImportPlaybook(file_content, filename):
    # function to import external Halberd playbooks 
    if file_content is not None:
        # base64 decoding file contents
        content_type, content_string = file_content.split(',')
        decoded_content = base64.b64decode(content_string)
        
        # save playbook to playbooks directory
        playbook_filepath = os.path.join("./automator/Playbooks", filename)
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
    pb_file = f"./automator/Playbooks/{name}.yml"

    # update playbook file
    with open(pb_file, "w") as file:
        yaml.dump(playbook_config, file)


def run_schedule(pb, time):
    # run schedules config
    schedules_file = "./automator/Schedules.yml"
    with open(schedules_file, "r") as schedule_data:
        schedules = yaml.safe_load(schedule_data)

    for schedule in schedules:
        pb = schedule['Playbook_Id']
        schedule.every(10).seconds.do(pb)
