import logging
import sys
from typing import Optional

class ColoredFormatter(logging.Formatter):
    """
    Custom formatter to add colors to log levels.
    """
    grey = "\x1b[38;20m"
    cyan = "\x1b[36;20m"
    green = "\x1b[32;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    reset = "\x1b[0m"
    # Format: Time - Logger - [COLOR]LEVEL[RESET] - Message
    # We construct the levelname part dynamically
    
    FORMATS = {
        logging.DEBUG: cyan,
        logging.INFO: green,
        logging.WARNING: yellow,
        logging.ERROR: red,
        logging.CRITICAL: bold_red
    }

    def format(self, record):
        color = self.FORMATS.get(record.levelno, self.reset)
        # Apply color only to the levelname
        # We temporarily modify the levelname in the record (copying would be safer but this is standard)
        original_levelname = record.levelname
        record.levelname = f"{color}{original_levelname}{self.reset}"
        
        # Format: CPD-SEC - [LEVEL] - Message
        formatter = logging.Formatter(f"CPD-SEC - [%(levelname)s] - %(message)s")
        result = formatter.format(record)
        
        # Restore original levelname to avoid side effects
        record.levelname = original_levelname
        return result

def setup_logger(verbose: bool = False, quiet: bool = False, log_level: Optional[str] = None):
    """
    Configure the logger based on verbosity flags or explicit log level.
    """
    logger = logging.getLogger("cpd")
    
    # Remove existing handlers to avoid duplicates if setup is called multiple times
    if logger.handlers:
        logger.handlers = []

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColoredFormatter())
    logger.addHandler(handler)

    if log_level:
        level = getattr(logging, log_level.upper(), None)
        if isinstance(level, int):
            logger.setLevel(level)
        else:
            logger.setLevel(logging.INFO)
            logger.warning(f"Invalid log level '{log_level}', defaulting to INFO")
    elif quiet:
        logger.setLevel(logging.WARNING)
    elif verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    return logger

logger = logging.getLogger("cpd")
