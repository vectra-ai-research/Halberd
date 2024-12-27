AUTOMATOR_DIR = "./automator"
AUTOMATOR_PLAYBOOKS_DIR = AUTOMATOR_DIR+"/Playbooks"
AUTOMATOR_OUTPUT_DIR = AUTOMATOR_DIR+"/Outputs"
AUTOMATOR_SCHEDULES_FILE = AUTOMATOR_DIR+"/Schedules.yml"
AUTOMATOR_EXPORTS_DIR = AUTOMATOR_DIR+"/Exports"

APP_LOCAL_DIR = "./local"
APP_LOG_FILE = APP_LOCAL_DIR+"/app.log"
MSFT_TOKENS_FILE = APP_LOCAL_DIR+"/MSFT_Graph_Tokens.yml"
GCP_CREDS_FILE = APP_LOCAL_DIR+"/GCP_Service_Account.json"
TECHNIQUE_OUTPUT_DIR = APP_LOCAL_DIR+"/technique_output"

OUTPUT_DIR = "./output"
REPORT_DIR = "./report"

GRAPH_ENDPOINT_URL = "https://graph.microsoft.com/v1.0"

LOGGING_CONFIG_FILE = "./core/logging/logging_config.yml"

CATEGORY_MAPPING = {
    "azure": "Azure",
    "entra_id": "EntraID",
    "m365": "M365",
    "aws": "AWS", 
    "gcp": "GCP"
}