class PlaybookError(Exception):
    """Custom exception class for Playbook-related errors."""
    def __init__(self, message="Playbook Error Occured", error_type = None, error_operation = None):
        self.message = message
        self.error_type = error_type if error_type else "common"
        self.error_operation = error_operation if error_operation else "common"
        super().__init__(self.message)