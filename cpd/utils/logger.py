import logging
import sys

def setup_logger(verbose: bool = False, quiet: bool = False):
    """
    Configure the logger based on verbosity flags.
    """
    logger = logging.getLogger("cpd")
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    if quiet:
        logger.setLevel(logging.WARNING)
    elif verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    return logger

logger = logging.getLogger("cpd")
