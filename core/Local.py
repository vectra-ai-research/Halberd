import csv
from datetime import datetime
from pathlib import Path

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
    if Path("./local/App_Log.csv").exists():
        pass
    else:
        log_file = "./local/App_Log.csv"
        f = open(log_file,"a")

        fields = ["date_time", "action","result"]
        log_input = {"date_time": "date_time", "action":"action", "result":"result"}

        write_log = csv.DictWriter(f, fieldnames= fields)
        write_log.writerow(log_input)
        print("App_Log file created.")


    if Path("./local/Trace_Log.csv").exists():
        pass
    else:
        log_file = "./local/Trace_Log.csv"
        f = open(log_file,"a")

        fields = ["date_time", "technique", "tactic","attack_surface","result"]
        log_input = {"date_time":"date_time", "technique":"technique", "tactic":"tactic","attack_surface":"attack_surface", "result":"result"}

        write_log = csv.DictWriter(f, fieldnames= fields)
        write_log.writerow(log_input)
        print("Trace_Log file created.")