from core.logging import logger
from core.parser import ConfParser
from core.redis import rds
from core.utils import Utils


class Register:
    def __init__(self):
        self.rds = rds
        self.utils = Utils()
        self.scan_in_progress_statuses = ['running', 'created', ]

    def is_scan_in_progress(self):
        session_state = rds.get_session_state()
        return session_state in self.scan_in_progress_statuses

    def scan(self, scan):
        if self.is_scan_in_progress():
            return (False, 429, 'There is already a scan in progress!')

        cfg = ConfParser(scan)
        self.rds.clear_session()
        self.rds.create_session()

        logger.info('Storing the new configuration')
        self.rds.store_json('sess_config', scan)

        networks = cfg.get_cfg_networks()
        if networks:
            logger.info('Scheduling network(s): {}'.format(', '.join(networks)))

        domains = cfg.get_cfg_domains()
        if domains:
            logger.info('Scheduling domains(s): {}'.format(', '.join(domains)))

        return (True, 200, 'Registered a new scan successfully!')
