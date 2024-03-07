import yaml

def TechniqueMapGenerator():
    '''Function to generate list of available techniques for each attack surface'''
    '''Function to run once at the start of application'''
    master_record_file = "./Techniques/MasterRecord.yml"
    techniques_map_file = "./Techniques/TechniquesMap.yml"

    with open(master_record_file, "r") as master_record_data:
        techniques_info = yaml.safe_load(master_record_data)

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

    with open(techniques_map_file, "w") as file:
        yaml.dump(technique_map, file)

    print("[*] Technique Map Updated")
    return Entra_Id_Technqiues, Azure_Technqiues, AWS_Technqiues, M365_Technqiues