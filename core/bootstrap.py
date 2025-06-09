import logging
import yaml
import csv
import shutil
from pathlib import Path

class Bootstrapper:
    """Handles initialization of application requirements."""
    
    def __init__(self, base_dir: str = "."):
        self.base_dir = Path(base_dir)
        self.logger = logging.getLogger("initialization")
        
        # Path constants
        self.APP_LOCAL_DIR = self.base_dir / "local"
        self.OUTPUT_DIR = self.base_dir / "output"
        self.REPORT_DIR = self.base_dir / "report"
        self.CHATS_DIR = self.APP_LOCAL_DIR / "chats"
        self.APP_LOG_FILE = self.APP_LOCAL_DIR / "app.log"
        self.MSFT_TOKENS_FILE = self.APP_LOCAL_DIR / "MSFT_Graph_Tokens.yml"
        self.AUTOMATOR_DIR = self.base_dir / "automator"
        self.AUTOMATOR_PLAYBOOKS_DIR = self.AUTOMATOR_DIR / "Playbooks"
        self.AUTOMATOR_OUTPUT_DIR = self.AUTOMATOR_DIR / "Outputs"
        self.AUTOMATOR_EXPORTS_DIR = self.AUTOMATOR_DIR / "Exports"
        self.AUTOMATOR_SCHEDULES_FILE = self.AUTOMATOR_DIR / "Schedules.yml"
        self.LOGGING_CONFIG_FILE = self.base_dir / "core" / "logging" / "logging_config.yml"
        
    def initialize(self):
        """
        Initialize all required application resources.
        """
        self._create_base_directories()
        self._setup_app_log_file()
        self._setup_msft_tokens()
        self._setup_automator()
        self._check_azure_cli()
        
    def _create_base_directories(self) -> None:
        """Create required base application directories."""
        directories = [
            self.APP_LOCAL_DIR,
            self.OUTPUT_DIR,
            self.REPORT_DIR,
            self.CHATS_DIR
        ]
        
        for directory in directories:
            if not directory.exists():
                self.logger.info(f"Creating directory: {directory}")
                directory.mkdir(parents=True, exist_ok=True)
                
    def _setup_app_log_file(self) -> None:
        """Setup application log file with CSV structure."""
        if not self.APP_LOG_FILE.exists():
            self.APP_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(self.APP_LOG_FILE, "a", newline='') as f:
                fields = ["date_time", "action", "result"]
                log_input = {
                    "date_time": "date_time",
                    "action": "action",
                    "result": "result"
                }
                write_log = csv.DictWriter(f, fieldnames=fields)
                write_log.writerow(log_input)
            self.logger.info("Application log file created")
                
    def _setup_msft_tokens(self) -> None:
        """Setup Microsoft tokens file."""
        if not self.MSFT_TOKENS_FILE.exists():
            self.MSFT_TOKENS_FILE.parent.mkdir(parents=True, exist_ok=True)
            all_tokens_data = {'AllTokens': []}
            with open(self.MSFT_TOKENS_FILE, 'w') as file:
                yaml.dump(all_tokens_data, file)
            self.logger.info("Microsoft tokens file created")
                
    def _setup_automator(self) -> None:
        """Setup automator directories and files."""
        # Create main automator directory if it doesn't exist
        if not self.AUTOMATOR_DIR.exists():
            self.AUTOMATOR_DIR.mkdir(parents=True, exist_ok=True)
            
        # Create all required automator subdirectories
        automator_dirs = [
            self.AUTOMATOR_PLAYBOOKS_DIR,
            self.AUTOMATOR_OUTPUT_DIR,
            self.AUTOMATOR_EXPORTS_DIR
        ]
        
        for directory in automator_dirs:
            if not directory.exists():
                directory.mkdir(parents=True, exist_ok=True)
                self.logger.info(f"Created automator directory: {directory.name}")
                
        # Create schedules file if it doesn't exist
        if not self.AUTOMATOR_SCHEDULES_FILE.exists():
            self.AUTOMATOR_SCHEDULES_FILE.touch()
            self.logger.info("Automator schedules file created")
            
    def _check_azure_cli(self) -> None:
        """Check Azure CLI installation."""
        if not self._is_azure_cli_installed():
            warning = '''
            Warning : Azure CLI Not Detected
            --------------------------------
            Azure CLI (az) was not found on this system. This is only required if you plan to 
            use Azure modules in your application.

            If you will be testing Azure modules:
            1. Install Azure CLI from: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli
            2. Ensure the installation directory is added to your system PATH
            3. Restart your terminal or IDE after installation

            If you are not using Azure modules, this warning can be safely ignored.
            '''
            print(warning)
            
    @staticmethod
    def _is_azure_cli_installed() -> bool:
        """Check if Azure CLI is installed."""
        return shutil.which('az') is not None