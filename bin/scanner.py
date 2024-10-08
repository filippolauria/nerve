import time

from core.redis import rds
from core.logging import logger
from core.port_scanner import Scanner
from core.parser import ConfParser


def scanner():
    scanner = Scanner()

    logger.info('Scanner process started')

    while True:
        if not rds.is_session_active():
            time.sleep(10)
            continue

        conf = rds.get_scan_config()

        if not conf:
            time.sleep(10)
            continue

        parsed_config = ConfParser(conf)

        hosts = rds.get_ips_to_scan(limit=parsed_config.get_cfg_scan_threads())

        if hosts:
            scan_data = scanner.scan(
                hosts,
                max_ports=parsed_config.get_cfg_max_ports(),
                custom_ports=parsed_config.get_cfg_custom_ports(),
                interface=parsed_config.get_cfg_netinterface()
            )

            if scan_data:
                for host, values in scan_data.items():
                    if 'ports' in values and values['ports']:
                        logger.info(f"Discovered Asset: {host}")
                        logger.debug('Host: {}, Open Ports: {}'.format(host, values['ports']))
                        rds.store_topology(host)
                        rds.store_sca(host, values)
                        rds.store_inv(host, values)
                        continue

                    if values['status_reason'] == 'echo-reply':
                        logger.info(f"Discovered Asset: {host}")
                        rds.store_topology(host)
