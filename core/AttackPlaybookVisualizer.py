from dash import html
import yaml
import dash_cytoscape as cyto
from core.Automator import Playbook, GetAllPlaybooks

master_record_file = "./Techniques/MasterRecord.yml"
with open(master_record_file, "r") as master_record_data:
    techniques_info = yaml.safe_load(master_record_data)

def AttackSequenceVizGenerator(playbook_name):

    if playbook_name == None:
        return html.Div([
            html.H3("No Selection"),
            ], style={"textAlign": "center", "padding-top": "50px"})
    
    else:
        for pb in GetAllPlaybooks():
            pb_config = Playbook(pb)
            if pb_config.name == playbook_name:
                pb_sequence = pb_config.sequence
                break
        
        # initialize array for cytoscope
        attack_sequence_viz_elements = []
        n = 0
        position_x = 50

        for step in pb_sequence:
            step_module_id = pb_sequence[step]['Module']
            step_wait = pb_sequence[step]['Wait']
            attack_sequence_viz_elements.append({'data': {'id': str(n), 'label': f"{step_module_id}: {techniques_info[step_module_id]['Name']}"}, 'position': {'x': position_x, 'y': 50}})
            position_x += 70
            n += 1

            attack_sequence_viz_elements.append({'data': {'id': str(n), 'label': str(step_wait)}, 'position': {'x': position_x, 'y': 50}, 'classes': 'timenode'})
            position_x += 70
            n += 1
        
        while n>1:
            n = n-1
            attack_sequence_viz_elements.append({'data': {'source': str(n-1), 'target': str(n)}})
        
        return cyto.Cytoscape(
                id='auto-attack-sequence-cytoscape-nodes',
                layout={'name': 'preset'},
                style={'height': '38vh'},
                elements= attack_sequence_viz_elements,
                stylesheet=[
                    # Add styles for the graph here
                    {
                        'selector': 'node',
                        'style': {
                            'label': 'data(label)',
                            'background-color': '#ff0000',
                            'color': '#fff',
                            'width': '40px',
                            'height': '40px',
                            'text-halign': 'center',
                            'text-valign': 'center',
                            'text-wrap': 'wrap',
                            'text-max-width': '50',
                            'font-size': '5px',
                            'shape': 'square'
                        }
                    },
                    {
                        'selector': 'edge',
                        'style': {
                            'curve-style': 'bezier',
                            'target-arrow-shape': 'triangle',
                            'line-color': '#000000',
                            'target-arrow-color': '#000000',
                        }
                    },
                    {
                        'selector': '.timenode',
                        'style': {
                            'label': 'data(label)',
                            'background-color': '#000000',
                            'color': '#fff',
                            'text-halign': 'center',
                            'text-valign': 'center',
                            'text-wrap': 'wrap',
                            'text-max-width': '20px',
                            'shape': 'ellipse',
                            'opacity': 0.7,
                            'width': '20px',
                            'height': '20px',
                        }
                    }
                ]
                )
    

def EnrichNodeInfo(node_data):
    selected_module_info = techniques_info[node_data]
    return selected_module_info