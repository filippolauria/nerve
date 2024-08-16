import logging

from config import APP_NAME, LOG_LEVEL, WEB_LOG_PATH
from sys import stdout


logger = logging.getLogger(APP_NAME)
level = logging.getLevelName(LOG_LEVEL)
logger.setLevel(level)

ch = logging.StreamHandler(stdout)
ch.setLevel(level)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(process)d - %(message)s')
ch.setFormatter(formatter)

fh = logging.FileHandler(WEB_LOG_PATH)
fh.setFormatter(formatter)
fh.setLevel(level)

logger.addHandler(fh)
logger.addHandler(ch)
