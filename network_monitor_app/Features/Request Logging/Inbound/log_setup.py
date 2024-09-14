import logging
from logging.handlers import RotatingFileHandler

def setup_logging():
    # Configure logging
    log_formatter = logging.Formatter('%(asctime)s - %(message)s')

    log_file = 'logs/inbound_requests.log'

    handler = RotatingFileHandler(
        log_file,
        mode='a',
        maxBytes=5 * 1024 * 1024,  # 5 MB per file
        backupCount=5,
        encoding=None,
        delay=0
    )

    handler.setFormatter(log_formatter)
    handler.setLevel(logging.INFO)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
