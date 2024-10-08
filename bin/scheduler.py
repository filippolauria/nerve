from core.logging import logger
from core.mailer import send_email
from core.parser import ConfParser
from core.redis import rds
from core.utils import Network, Integration
from ipaddress import ip_network
from time import sleep


def ip_in_excluded_network(ip_obj, excluded_networks):
    exclude = False
    for excluded_network in excluded_networks:
        excluded_network_obj = ip_network(excluded_network)
        if ip_obj in excluded_network_obj:
            exclude = True
            break

    return exclude


def schedule_ips(networks, excluded_networks=None):
    networks = list(set(networks))
    if excluded_networks:
        excluded_networks = list(set(excluded_networks))

    for network in networks:
        try:
            network_obj = ip_network(network, strict=False)

            for ip_obj in network_obj:

                if excluded_networks and ip_in_excluded_network(ip_obj, excluded_networks):
                    continue

                rds.store_sch(str(ip_obj))

        except ValueError as e:
            logger.info(f'Error while scheduling IP addresses: {e}')


def schedule_domains(domains):
    domains = list(set(domains))

    for domain in domains:
        rds.store_sch(domain)


def scheduler():
    logger.info('Scheduler process started')
    net_utils = Network()
    int_utils = Integration()

    while True:
        sleep(10)
        session_state = rds.get_session_state()

        if not session_state or session_state != 'created':
            continue

        config = rds.get_scan_config()

        if not config:
            continue

        conf = ConfParser(config)
        networks = conf.get_cfg_networks()
        domains = conf.get_cfg_domains()
        excluded_networks = conf.get_cfg_exc_networks()
        excluded_networks.append(net_utils.get_primary_ip() + '/32')
        frequency = conf.get_cfg_frequency()

        rds.start_session()

        if networks:
            schedule_ips(networks, excluded_networks)

        if domains:
            schedule_domains(domains)

        checks = 0

        while True:
            checks = 0 if rds.is_session_active() else checks + 1

            if checks == 10:
                logger.info('Session is about to end...')
                webhook = conf.get_cfg_webhook()
                vuln_data = rds.get_vuln_data()

                logger.info('Post assessment actions will now be taken...')
                if webhook:
                    int_utils.submit_webhook(
                        webhook,
                        cfg=conf.get_raw_cfg(),
                        data=vuln_data
                    )

                if frequency == 'once':
                    email_settings = rds.get_email_settings()
                    if email_settings:
                        logger.info('Sending email...')
                        email_settings['action'] = 'send'
                        send_email(email_settings, vuln_data)

                    slack_settings = rds.get_slack_settings()
                    if slack_settings:
                        int_utils.submit_slack(
                            hook=slack_settings,
                            data=vuln_data
                        )

                rds.end_session()
                break

            sleep(20)
