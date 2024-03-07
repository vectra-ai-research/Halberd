import yaml

def TacticMapGenerator():
    '''Function to generate list of available tactics for each attack surface'''
    '''Function to run once at the start of application'''
    master_record_file = "./Techniques/MasterRecord.yml"
    tactics_map_file = "./Techniques/TacticsMap.yml"

    with open(master_record_file, "r") as master_record_data:
        techniques_info = yaml.safe_load(master_record_data)

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

    with open(tactics_map_file, "w") as file:
        yaml.dump(tactics_map, file)
    
    print("[*] Tactic Map Updated")

    return Entra_Id_Tactics, Azure_Tactics, AWS_Tactics, M365_Tactics