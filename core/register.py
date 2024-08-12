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
        scan_status = rds.get_session_state().strip().lower()
        return scan_status in self.scan_in_progress_statuses

    def scan(self, scan):
        if self.is_scan_in_progress():
            return (False, 429, 'There is already a scan in progress!')

        cfg = ConfParser(scan)
        self.rds.clear_session()
        self.rds.create_session()

        logger.info('Storing the new configuration')
        self.rds.store_json('sess_config', scan)

        networks = cfg.get_cfg_networks()
        domains = cfg.get_cfg_domains()

        if networks:
            logger.info('Scheduling network(s): {}'.format(', '.join(networks)))
        if domains:
            logger.info('Scheduling domains(s): {}'.format(', '.join(domains)))

        return (True, 200, 'Registered a new scan successfully!')
