import logging
import json
from typing import Any, Dict
import yaml
from logging.handlers import RotatingFileHandler
from core.Constants import LOGGING_CONFIG_FILE

class StructuredAppLog:
    """
    A class to create structured log messages.

    This class allows for the creation of log messages with additional
    key-value pairs, which can be easily parsed and analyzed later.

    Attributes:
        message (str): The main log message.
        kwargs (Dict[str, Any]): Additional key-value pairs for structured logging.
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        """
        Initialize a StructuredMessage instance.

        Args:
            message (str): The main log message.
            **kwargs: Arbitrary keyword arguments for additional structured data.
        """
        self.message = message
        self.kwargs = kwargs

    def __str__(self) -> str:
        """
        Convert the structured message to a string representation.

        Returns:
            str: A string containing the message and JSON-formatted key-value pairs.
        """
        return f"{self.message} {json.dumps(self.kwargs)}"

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load the logging configuration from a YAML file.

    Args:
        config_path (str): Path to the YAML configuration file.

    Returns:
        Dict[str, Any]: A dictionary containing the logging configuration.
    """
    with open(config_path, 'r') as config_file:
        return yaml.safe_load(config_file)

def setup_logger(logger_name: str, config_path: str = LOGGING_CONFIG_FILE) -> logging.Logger:
    """
    Set up and configure a logger based on a YAML configuration file.

    This function creates a logger with handlers specified in the config file.
    It supports console output and rotating file output.

    Args:
        config_path (str): Path to the YAML configuration file. Defaults to 'logging_config.yaml'.

    Returns:
        logging.Logger: A configured logger instance.
    """
    full_config = load_config(config_path)
    config = full_config['loggers'][logger_name]
    logger = logging.getLogger(name=logger_name)
    logger.setLevel(full_config['logger_level'])

    # Console handler
    if config['console_handler']['enabled']:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(config['console_handler']['level'])
        console_formatter = logging.Formatter(config['console_handler']['format'])
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    # Rotating file handler
    if config['file_handler']['enabled']:
        file_handler = RotatingFileHandler(
            filename=config['file_handler']['filename'],
            maxBytes=config['file_handler']['max_bytes'],
            backupCount=config['file_handler']['backup_count']
        )
        file_handler.setLevel(config['file_handler']['level'])
        file_formatter = logging.Formatter(config['file_handler']['format'])
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger

# Intialize loggers
app_logger = setup_logger("app") # Initialize Halberd logger
graph_logger = setup_logger("ms_graph") # Initialize graph requests logger