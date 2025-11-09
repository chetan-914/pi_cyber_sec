# pi_cyber_sec/utils/logger.py

import logging
import sys

def setup_logger(name: str, level=logging.INFO):
    """
    Sets up a configured logger.

    :param name: The name of the logger.
    :param level: The logging level (e.g., logging.INFO).
    :return: A configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid adding multiple handlers if logger is already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    return logger