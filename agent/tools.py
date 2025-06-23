from attack_techniques.technique_registry import *
from core.entra.entra_token_manager import EntraTokenManager
from core.azure.azure_access import AzureAccess
from core.gcp.gcp_access import GCPAccess
from core.aws.aws_session_manager import SessionManager
from core.output_manager.output_manager import OutputManager
from core.logging.logger import app_logger,StructuredAppLog
from core.Constants import *
import uuid
import datetime
import boto3
from typing import Optional, Dict, List, Tuple, Any

tools = [
    {
        "name": "execute_technique",
        "description": "Executes a selected attack technique. Requires a technique ID (t_id) and technique input (technique_input) as inputs. The technique ID is the Halberd technique to execute. Returns a tuple of the execution event id, message indicating execution result, filepath of output stored and the actual output from the technique execution. Example tool response format: ('event-id', 'Success', 'Full-Technique-Output').",
        "input_schema": {
            "type": "object",
            "properties": {
                "t_id": {
                    "type": "string",
                    "description": "The ID of the Halberd technique to be executed."
                },
                "technique_input": {
                    "type": "object",
                    "description": "A dictionary of the Halberd technique's input fields and their respective values. Input fields for a technique can be obtained using get_technique_inputs tool"
                }
            },
            "required": ["t_id"]
        },
        "cache_control": {"type": "ephemeral"}
    },
    {
        "name": "get_technique_inputs",
        "description": "Gets the input configuration of a particular technique. The tool returns a dictionary containing all inputs required and supported by a technique along with the input type, description and additional information about each input. Empty dictionary indicates no inputs are required by the technique.",
        "input_schema": {
            "type": "object",
            "properties": {
                "t_id": {
                    "type": "string",
                    "description": "The ID of the Halberd technique to be executed"
                }
            },
            "required": ["t_id"]
        },
        "cache_control": {"type": "ephemeral"}
    },
    {
        "name": "get_technique_aztrm_info",
        "description": "Get a technique Azure Threat Research Matrix mapping",
        "input_schema": {
            "type": "object",
            "properties": {
                "t_id": {
                    "type": "string",
                    "description": "The ID of the Halberd technique"
                }
            },
            "required": ["t_id"]
        }
    },
    {
        "name": "get_technique_mitre_info",
        "description": "Get a Halberd technique Mitre technique mapping",
        "input_schema": {
            "type": "object",
            "properties": {
                "t_id": {
                    "type": "string",
                    "description": "The ID of the Halberd technique"
                }
            },
            "required": ["t_id"]
        }
    },
    {
        "name": "list_techniques",
        "description": "List available techniques in Halberd technique registry. Possible to get all or scoped results using the tool properties.",
        "input_schema": {
            "type": "object",
            "properties": {
                "attack_surface": {
                    "type": "string",
                    "description": "Attack surface name to filter tactics",
                    "enum": ['azure', 'entra_id', 'aws', 'm365', 'gcp']
                },
                "tactic": {
                    "type": "string",
                    "description": "MITRE tactic to filter techniques",
                    "enum": ['Collection', 'Credential Access', 'Defense Evasion', 'Discovery', 'Execution', 'Exfiltration', 'Impact', 'Initial Access', 'Lateral Movement', 'Persistence', 'Privilege Escalation']
                },
                "technique_id": {
                    "type": "string",
                    "description": "Technique ID to fetch a specific technique"
                }
            }
        },
        "cache_control": {"type": "ephemeral"}
    },
    {
        "name": "list_tactics",
        "description": "Returns a list of all tactics covered in Halberd technique registry. Possible to get all or scoped results using the tool properties.",
        "input_schema": {
            "type": "object",
            "properties": {
                "attack_surface": {
                    "type": "string",
                    "description": "Attack surface name to filter tactics"
                }
            }
        }
    },
    {
        "name": "entra_id_get_all_tokens",
        "description": "Returns list of all available access tokens (without refresh tokens)",
        "input_schema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "entra_id_get_active_token",
        "description": "Returns currently active microsoft Entra ID access token. Only use this when the raw access token is directly required for a task such as input for a technique or for decoding information from the access token.",
        "input_schema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "entra_id_get_active_token_pair",
        "description": "Returns currently active access token and its refresh token. Returns a tuple of (access_token, refresh_token), however both may be None. Use this tool when the raw access token & refresh token is directly required for a task.",
        "input_schema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "entra_id_set_active_token",
        "description": "Sets supplied token as active token in app. Active token is used by app as default to make graph requests.",
        "input_schema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "The access token string to set as active"
                }
            },
            "required": ["token"]
        }
    },
    {
        "name": "entra_id_decode_jwt_token",
        "description": "Decodes MSFT JWT and returns token information. Returns a dict with decoded token information",
        "input_schema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "The access token string to decode"
                }
            },
            "required": ["token"]
        }
    },
    {
      "name": "aws_get_all_sessions",
      "description": "List all established AWS sessions available currently.",
      "input_schema": {
          "type": "object",
          "properties": {}
      }
    },
    {
      "name": "aws_retrieve_sessions",
      "description": "Retrieve a specific AWS session by its name.",
      "input_schema": {
        "type": "object",
        "parameters": {
            "session_name": {
                "type": "string",
                "description": "The name of the session to retrieve"
          }
        },
        "required": ["session_name"]
      }
    },
    {
      "name": "aws_get_active_session",
      "description": "Retrieve the currently active AWS session.",
      "input_schema": {
        "type": "object",
        "properties": {}
      }
    },
    {
      "name": "aws_get_session_details",
      "description": "Retrieve details about a session in JSON format. If no session is specified, returns info for the active session.",
      "input_schema": {
        "type": "object",
        "properties": {}
      }
    },
    {
      "name": "aws_set_active_session",
      "description": "Set a session as the default/active session to be used across Halberd AWS techniques.",
      "input_schema": {
        "type": "object",
        "properties": {
          "session_name": {
            "type": "string",
            "description": "The name of the session to set as active"
          }
        },
        "required": ["session_name"]
      }
    },
    {
      "name": "aws_get_connected_user_details",
      "description": "Retrieve user details from the active session.",
      "input_schema": {
        "type": "object",
        "properties": {}
      }
    },
    {
      "name": "read_halberd_logs",
      "description": "Read the contents of Halberd log file, with an option to read only the last x lines. Returns lines from the log file as a list of strings.",
      "input_schema": {
        "type": "object",
        "properties": {
            "last_lines": {
            "type": "number",
            "description": "Number of last lines to read. If None, reads the entire file."
          }
        }
      }
    },
    {
      "name": "get_technique_execution_response",
      "description": "Retrieves output of a previously executed technique. Takes event_id as input which is a unique string associated with a particular execution event of a technique. Returns the raw response from the techniques execution. Use this tool to fetch the full response from a past technique execution. Event IDs can be found in Halberd log file along with other details associated with the event ID",
      "input_schema": {
        "type": "object",
        "properties": {
            "event_id": {
            "type": "string",
            "description": "Event ID of a technique execution event to retrive its output"
          }
        }
      }
    },
    {
    "name": "get_app_info",
    "description": "Retrieves application metadata and version information from the version.py file. Returns details about Halberd including version, description, author, license, repository, and supported cloud platforms. This tool provides information about the application itself and requires no input parameters.",
    "input_schema": {
        "type": "object",
        "properties": {},
        "required": []
    }
}
]

technique_registry = TechniqueRegistry

def list_techniques(attack_surface: str = None, tactic: str = None, technique_id: str = None) -> List[Dict]:
    """
    Returns a list of all techniques in technique registry
    :param attack_surface: Attack Surface to filter techniques
    :param tactic: MITRE tactic to filter techniques
    :param technique_id: technique class name to fetch a specific technique
    """
    technique_registry = TechniqueRegistry
    all_techniques = technique_registry().list_techniques()
    filtered_techniques = []

    for tech_id, tech_class in all_techniques.items():
        technique = tech_class()
        
        # Filter by category
        if attack_surface and not technique_registry.get_technique_category(tech_id) == attack_surface:
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
        tech_info = {
            "name": technique.name,
            "t_id": tech_id
        }

        filtered_techniques.append(tech_info)

    return filtered_techniques

def list_tactics(attack_surface: str = None) -> List[str]:
    """Returns a list of all tactics covered in technique registry"""
    try:
        return TechniqueRegistry.list_tactics(attack_surface)
    except ValueError as e:
        return []


def execute_technique(t_id: str, technique_input: dict):
    '''Executes a selected attack technique'''
    technique = technique_registry.get_technique(t_id)
    t_mitre_info = technique().get_mitre_info()
    tactic = t_mitre_info[0]['tactics'][0]

    # Technique attack surface / category
    attack_surface = TechniqueRegistry.get_technique_category(t_id)
    # Active entity / Source
    active_entity = "Unknown"

    if attack_surface in ["m365","entra_id"]:
        manager = EntraTokenManager()
        access_token = manager.get_active_token()
        
        if access_token:
            try:
                access_info = manager.decode_jwt_token(access_token)
                active_entity = access_info['Entity']
            except Exception as e:
                active_entity = "Unknown"
        else: 
            active_entity = "Unknown"
    
    if attack_surface == "aws":
        try:
            manager = SessionManager()
            # set default session
            sts_client = boto3.client('sts')
            session_info = sts_client.get_caller_identity()
            active_entity = session_info['UserId']
        except:
            active_entity = "Unknown"

    if attack_surface == "azure":
        try:
            current_access = AzureAccess().get_current_subscription_info()
            active_entity = current_access['user']['name']
        except:
            active_entity = "Unknown"

    # if attack_surface == "gcp":
    #     try:
    #         current_access = None
    #         if t_id == "GCPEstablishAccessAsServiceAccount":
    #             manager = GCPAccess(raw_credentials=file_content[0],name=values[0])
    #             current_access = manager.get_current_access().get("name")
    #             current_access = manager.get_detailed_credential(name=current_access)
    #         else:
    #             manager = GCPAccess()
    #             current_access = manager.get_current_access()
    #         if current_access["credential"]["type"] == "service_account":
    #             active_entity = current_access["credential"]["client_email"]
    #         if current_access["credential"]["type"] == "user_authorized":
    #             active_entity = current_access["credential"]["client_id"]

    #     except:
    #         active_entity = "Unknown"

    # Log technique execution start
    event_id = str(uuid.uuid4()) #Generate unique event_id for the execution
    
    app_logger.info(StructuredAppLog("Technique Execution",
        event_id = event_id,
        source = active_entity,
        status = "started",
        technique = t_id,
        tactic=tactic,
        timestamp=datetime.datetime.now().isoformat())
    )

    # Execute technique    
    output = technique().execute(**technique_input)
    
    # check if technique output is in the expected tuple format (success, response)
    if isinstance(output, tuple) and len(output) == 2:
        result, response = output

        # Initialize output manager
        output_manager = OutputManager()

        # Log technique execution
        app_logger.info(StructuredAppLog("Technique Execution",
            event_id = event_id,
            source = active_entity,
            status = "completed",
            result = result.value,
            technique = t_id,
            target = None,
            tactic=tactic,
            timestamp=datetime.datetime.now().isoformat())
        )

        output_data = response['value'] if result.value == "success" else response['error']
        # Save output to file
        output_file_path = output_manager.store_technique_output(
            data=output_data, 
            technique_name=t_id, 
            event_id=event_id
        )

        # Return results
        return event_id, result.value, output_file_path, output_data
    
    # Unexpected technique output
    return event_id, "Failed", ""

def get_technique_inputs(t_id: str) -> Dict:
    try:
        technique = technique_registry.get_technique(t_id)
        technique_params = (technique().get_parameters())

        return technique_params
    except:
        return {"error" : "Failed to get technique inputs"}

def get_technique_info(t_id: str):
    """Get a technique information such as definition, mitre mappings & azure threat research matrix mappings"""
    technique = TechniqueRegistry.get_technique(t_id)
    return technique.__dict__
    try:
        mitre_info = technique().get_mitre_info()
        return mitre_info
    except:
        return None
    
    try:
        mitre_info = technique().get_mitre_info()
        return mitre_info
    except:
        return None

def get_technique_mitre_info(t_id: str):
    """Get a technique Mitre technique mapping"""
    technique = TechniqueRegistry.get_technique(t_id)
    try:
        mitre_info = technique().get_mitre_info()
        return mitre_info
    except:
        return None

def get_technique_aztrm_info(t_id: str):
    """Get a technique Azure Threat Research Matrix mapping"""
    technique = TechniqueRegistry.get_technique(t_id)
    try:
        aztrm_info = technique().get_azure_trm_info()
        return aztrm_info
    except:
        return None

# Entra ID tools

def entra_id_get_all_tokens():
    """Returns list of all available access tokens (without refresh tokens)"""
    manager = EntraTokenManager()
    all_tokens = manager.get_all_tokens()
    return all_tokens
    
def entra_id_get_active_token():
    """Returns currently active MSFT access token"""
    manager = EntraTokenManager()
    active_token = manager.get_active_token()
    return active_token

def entra_id_get_active_token_pair():
    """
    Returns currently active access token and its refresh token
    
    Returns:
        Tuple of (access_token, refresh_token). Both may be None
    """
    manager = EntraTokenManager()
    active_token = manager.get_active_token_pair()
    return active_token

def entra_id_set_active_token(token):
    """
    Sets supplied token as active token in app. 
    Active token is used by app as default to make graph requests.
    
    Args:
        token_value: The access token string to set as active
    
    Raises:
        ValueError: If token not found in app
    """
    try:
        manager = EntraTokenManager()
        manager.set_active_token(token)
        return f"Active token set successfully : {token}"
    except:
        return "Failed to set active token"
    # Update access info div with selected token info
    return generate_entra_access_info(access_token=access_token)
    
def entra_id_decode_jwt_token(token:str):
    """
        Decodes MSFT JWT and returns token information
        
        Args:
            token_value: The access token to decode
            
        Returns:
            Dict with decoded token information
        """
    manager = EntraTokenManager()
    token_info = manager.decode_jwt_token(token)
    return token_info

def aws_get_all_sessions():
    """
    List all established sessions.
    
    :return: List of all AWS sessions available currently
    """
    manager = SessionManager()
    return manager.list_sessions()

def aws_retrieve_sessions(session_name):
    """
    Retrieve a session by its name.
    
    :param session_name: The name of the session to retrieve
    :return: The requested boto3.Session object, or None if not found
    """
    manager = SessionManager()
    return manager.get_session(session_name)

def aws_get_active_session():
    """
    Retrieve active session.
    
    :return: The active boto3.Session object, or None if not found
    """
    manager = SessionManager()
    return manager.get_active_session()

def aws_get_session_details():
    """
    Retrieve session details by its name in json format. If no session is specified, return info for active session.
    
    :param session_name: The name of the session to retrieve
    :return: session details, or an empty dict if not found
    """
    manager = SessionManager()
    return manager.get_session_details_as_json()

def aws_set_active_session(session_name):
    """
    Set a session as default/active session.This session is used across Halberd AWS techniques.

    :param session_name: The name of the session to set as active
    :raises ValueError: If the session is not found
    """
    manager = SessionManager()
    return manager.set_active_session(session_name)

def aws_get_connected_user_details():
    """
    Retrieves user detail from active session

    :return: A dictionary with user details, or None if no active session
    """
    manager = SessionManager()
    return manager.get_user_details()

def read_halberd_logs(last_lines: int):
    """
    Read the contents of Halberd log file, with an option to read only the last x lines.
    
    Args:
        last_lines (int, optional): Number of last lines to read. If None, reads the entire file.
        
    Returns:
        list: The lines from the log file as a list of strings.
        
    Raises:
        FileNotFoundError: If the specified file doesn't exist.
        ValueError: If last_lines is negative.
    """

    if last_lines is not None and last_lines < 0:
        raise ValueError("last_lines must be a non-negative integer")
    
    try:
        with open(APP_LOG_FILE, 'r') as file:
            if last_lines is None:
                # Read the entire file
                return file.readlines()
            else:
                # Using deque with maxlen - discard items from the other end
                from collections import deque
                return list(deque(file, maxlen=last_lines))
    except FileNotFoundError:
        raise FileNotFoundError(f"The file '{APP_LOG_FILE}' was not found.")
    
def get_technique_execution_response(event_id):
    """
    Retrieves output of a previously executed technique. Takes in event_id as input which is a unique string associated with a particular technique execution. Returns the raw response from the techniques execution.
    Args:
        event_id (string, optional): Event ID to retrive the output for.
    """
    # Initialize output manager
    output_manager = OutputManager()
    # Get technique execution output by event id
    event_output = output_manager.get_output_by_event_id(event_id=event_id)

    return event_output['data']

def get_app_info() -> Dict[str, Any]:
    """
    Retrieves application metadata and version information from version.py

    Returns:
        Dict[str, Any]: Dictionary containing app metadata including version, description, author, license, repository, and supported clouds
    """
    try:
        import version
        return {
            "version": getattr(version, '__version__', 'Unknown'),
            "name": getattr(version, '__name__', 'Unknown'),
            "description": getattr(version, '__description__', 'Unknown'),
            "repository": getattr(version, '__repository__', 'Unknown'),
            "author": getattr(version, '__author__', 'Unknown'),
            "license": getattr(version, '__license__', 'Unknown'),
            "supported_clouds": getattr(version, '__cloud__', []),
            "status": "success"
        }
        
    except:
        # Return static information
        return {
            "version": 3,
            "name": "Halberd : Multi-Cloud Agentic Attack Tool",
            "description": "Halberd is an advanced multi-cloud attack tool designed for security teams to validate cloud defenses through sophisticated attack emulation.",
            "repository": "https://github.com/vectra-ai-research/Halberd",
            "author": "Arpan Sarkar (@openrec0n)",
            "license": "GPL-3.0",
            "supported_clouds": ["Entra ID", "M365", "Azure", "AWS", "GCP"],
            "status": "success"
        }