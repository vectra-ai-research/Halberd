import argparse
import json
from typing import List, Dict
from attack_techniques.technique_registry import TechniqueRegistry

def list_techniques(category: str = None, tactic: str = None, technique_id: str = None) -> List[Dict]:
    """
    Returns a list of all techniques in technique registry
    :param category: Category to filter techniques
    :param tactic: MITRE tactic to filter techniques
    :param technique_id: technique class name to fetch a specific technique
    """
    technique_registry = TechniqueRegistry
    all_techniques = technique_registry().list_techniques()
    filtered_techniques = []

    for tech_name, tech_class in all_techniques.items():
        technique = tech_class()
        
        # Filter by category
        if category and not technique_registry.get_technique_category(tech_name) == category:
            continue
        
        # Filter by tactic
        if tactic:
            tactic_match = any(tactic.lower() in mt.tactics for mt in technique.mitre_techniques)
            if not tactic_match:
                continue
        
        # Filter by technique ID
        if technique_id:
            id_match = any(technique_id.upper() == mt.technique_id for mt in technique.mitre_techniques)
            if not id_match:
                continue
        
        tech_info = {
            "name": technique.name,
            "description": technique.description,
            "mitre_techniques": [
                {
                    "id": mt.technique_id,
                    "name": mt.technique_name,
                    "tactics": mt.tactics,
                    "sub_technique_name": mt.sub_technique_name,
                    "url": mt.mitre_url
                } for mt in technique.mitre_techniques
            ]
        }
        filtered_techniques.append(tech_info)
    
    return filtered_techniques

def list_tactics(category: str = None) -> List[str]:
    """Returns a list of all tactics covered in technique registry"""
    try:
        return TechniqueRegistry.list_tactics(category)
    except ValueError as e:
        print(f"Error: {str(e)}")
        return []
    
def get_technique_category(technique_name: str) -> str:
    """Returns the category/attack surface of a given technique"""
    category = TechniqueRegistry.get_technique_category(technique_name)
    if category:
        return category
    else:
        return f"Unable to determine the category for technique '{technique_name}'. The technique might not exist or might not be properly registered."


def main():
    parser = argparse.ArgumentParser(description="Security Testing CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # List techniques command
    list_techniques_parser = subparsers.add_parser("list-techniques", help="List techniques")
    list_techniques_parser.add_argument("--category", choices=['azure', 'entra_id', 'aws', 'm365'], help="Filter techniques by category")
    list_techniques_parser.add_argument("--tactic", help="Filter techniques by MITRE tactic")
    list_techniques_parser.add_argument("--technique-id", help="Filter techniques by MITRE technique ID")

    # List tactics command
    list_tactics_parser = subparsers.add_parser("list-tactics", help="List MITRE tactics")
    list_tactics_parser.add_argument("--category", choices=['azure', 'entra_id', 'aws', 'm365'], help="Filter tactics by category")

    # Get technique category command
    get_category_parser = subparsers.add_parser("get-category", help="Get category of a technique")
    get_category_parser.add_argument("technique_name", help="Name of the technique")

    # Execute command
    execute_parser = subparsers.add_parser("execute", help="Execute a technique")
    execute_parser.add_argument("technique", help="Technique to execute")
    execute_parser.add_argument("--params", type=json.loads, help="Technique parameters in JSON format")

    args = parser.parse_args()

    if args.command == "list-techniques":
        techniques = list_techniques(args.category, args.tactic, args.technique_id)
        print(json.dumps(techniques, indent=2))
    elif args.command == "list-tactics":
        tactics = list_tactics(args.category)
        print(json.dumps(tactics, indent=2))
    elif args.command == "get-category":
        print(get_technique_category(args.technique_name))
    elif args.command == "execute":
        try:
            technique_class = TechniqueRegistry.get_technique(args.technique)
            technique = technique_class()
            status, result = technique.execute(**(args.params or {}))
            print(json.dumps({
                "status": status.value,
                "result": result
            }, indent=2))
        except (ValueError, TypeError) as e:
            print(json.dumps({
                "status": "error",
                "result": {"error": str(e)}
            }, indent=2))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()