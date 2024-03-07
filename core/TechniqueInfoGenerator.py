'''Generates Technique information offcanvas on the attack page'''
import yaml
from dash import dcc, html

master_record_file = "./Techniques/MasterRecord.yml"
with open(master_record_file, "r") as master_record_data:
    techniques_info = yaml.safe_load(master_record_data)

def TechniqueRecordInfo(t_id):

    technique_info_div = []

    technique_name = techniques_info[t_id]['Name']
    technique_info_div.append(html.H1(technique_name))
    technique_info_div.append(html.Br())

    t_attack_surface = techniques_info[t_id]['AttackSurface']
    technique_info_div.append(html.H2("Attack Surface :", className="text-success"))
    technique_info_div.append(html.H4(t_attack_surface))
    technique_info_div.append(html.Br())

    t_mitre_info = techniques_info[t_id]['References']['MITRE']
    technique_info_div.append(html.H2("MITRE Info :"))
    technique_info_div.append(html.Br())

    for mitre_technique_id in t_mitre_info:
        # Technique ID
        technique_info_div.append(html.H3("Technique ID :", className="text-success"))
        if mitre_technique_id:
            technique_info_div.append(html.H4(mitre_technique_id))
        else:
            technique_info_div.append(html.H4("N/A"))
        technique_info_div.append(html.Br())

        # Technique Name
        t_mitre_technique = t_mitre_info[mitre_technique_id]['Technique']
        technique_info_div.append(html.H3("Technique :", className="text-success"))
        if t_mitre_technique:
            technique_info_div.append(html.H4(t_mitre_technique))
        else:
            technique_info_div.append(html.H4("N/A"))
        technique_info_div.append(html.Br())

        # Sub-technique
        t_mitre_subtechnique = t_mitre_info[mitre_technique_id]['SubTechnique']
        technique_info_div.append(html.H3("Sub-Technique :", className="text-success"))
        if t_mitre_subtechnique:
            technique_info_div.append(html.H4(t_mitre_subtechnique))
        else:
            technique_info_div.append(html.H4("N/A"))
        technique_info_div.append(html.Br())

        # Tactics
        t_mitre_tactics = t_mitre_info[mitre_technique_id]['Tactic']
        technique_info_div.append(html.H3("Tactics :", className="text-success"))
        technique_info_div.append(html.H4(", ".join(t_mitre_tactics)))
        technique_info_div.append(html.Br())

    #Resources
    technique_resources = techniques_info[t_id]['Resources']
    technique_info_div.append(html.H2("Resources :", className="text-success"))
    for resource in technique_resources:
        technique_info_div.append(dcc.Link(href = resource, target = "_blank"))
    
    technique_info_div.append(html.Br())
    technique_info_div.append(html.Br())

    #Notes
    if techniques_info[t_id]['Notes']:
        technique_notes = techniques_info[t_id]['Notes']
        technique_info_div.append(html.H2("Notes :", className="text-success"))
        for note in technique_notes:
            technique_info_div.append(html.H4(html.Li(note)))
        
        technique_info_div.append(html.Br())

    return technique_info_div