from dash import dcc, html
import yaml

def TechniqueOptionsGenerator(tab, tactic):

    master_record_file = "./Techniques/MasterRecord.yml"
    technique_map_file = "./Techniques/TechniquesMap.yml"

    with open(master_record_file, "r") as master_record_data:
        techniques_info = yaml.safe_load(master_record_data)

    with open(technique_map_file, "r") as technique_map_data:
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
                        "label": html.Div([techniques_info[technique]['Name']], style={'font-size': 20}, className="bg-dark text-body"),
                        "value": technique,
                    }
                )

    technique_options_element = [
        html.H2(tactic),
        dcc.RadioItems(id = "attack-options-radio", options = technique_options_list, value = technique_options_list[0]["value"], labelStyle={"display": "flex", "align-items": "center"}),
        ]

    return technique_options_element