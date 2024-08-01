'''
Name : Local.py
Description : Local functions to checks and initiate application files
'''
import csv
from datetime import datetime
from pathlib import Path
import os
import yaml

def WriteAppLog(action, result = "success"):
    log_file = "./local/App_Log.csv"
    f = open(log_file,"a")

    fields = ["date_time", "action","result"]
    log_input = {"date_time": str(datetime.today()), "action":action, "result":result}

    write_log = csv.DictWriter(f, fieldnames= fields)
    write_log.writerow(log_input)

    return True
    
def ReadAppLogger():
    log_file = "./local/App_Log.csv"
    f = open(log_file,"r")
    return csv.DictReader(f)

def ReadTraceLog():
    log_file = "./Trace_Log.csv"
    f = open(log_file,"r")
    return csv.DictReader(f)

def InitializationCheck():
    # Check for local folder
    if Path("./local").exists():
        pass
    else:
        os.makedirs("./local")

    # Check for application log file
    if Path("./local/App_Log.csv").exists():
        pass
    else:
        log_file = "./local/App_Log.csv"
        f = open(log_file,"a")

        fields = ["date_time", "action","result"]
        log_input = {"date_time": "date_time", "action":"action", "result":"result"}

        write_log = csv.DictWriter(f, fieldnames= fields)
        write_log.writerow(log_input)
        print("Application log file created")

    # Check for trace log file
    if Path("./local/Trace_Log.csv").exists():
        pass
    else:
        log_file = "./local/Trace_Log.csv"
        f = open(log_file,"a")

        fields = ["date_time", "technique", "tactic","attack_surface","result"]
        log_input = {"date_time":"date_time", "technique":"technique", "tactic":"tactic","attack_surface":"attack_surface", "result":"result"}

        write_log = csv.DictWriter(f, fieldnames= fields)
        write_log.writerow(log_input)
        print("Trace log file created")

    # check for msft tokens file
    if Path("./local/MSFT_Graph_Tokens.yml").exists():
        pass
    else:
        tokens_file = "./local/MSFT_Graph_Tokens.yml"
        all_tokens_data = {'AllTokens':[]}

        with open(tokens_file, 'w') as file:
            yaml.dump(all_tokens_data, file)

    # check for automator folder
    if Path("./automator").exists():
        # check for automtor/Playbooks folder
        if Path("./automator/Playbooks").exists():
            pass
        else:
            os.makedirs("./automator/Playbooks")
        
        # check for automator/Outputs folder
        if Path("./automator/Outputs").exists():
            pass
        else:
            os.makedirs("./automator/Outputs")

        # check for automator/Schedules.yml file
        if Path("./automator/Schedules.yml").exists():
            pass
        else:
            # create Schedules.yml config file
            with open("./automator/Schedules.yml", 'w') as file:
                pass
            
    else:
        # create all automator dirs and files
        os.makedirs("./automator")
        os.makedirs("./automator/Playbooks")
        os.makedirs("./automator/Outputs")
        with open("./automator/Schedules.yml", 'w') as file:
            pass