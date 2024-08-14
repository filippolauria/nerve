import time
import threading

from core.manager import rule_manager
from core.logging import logger
from core.redis import rds


def run_rules(conf):
    data = rds.get_scan_data()
    exclusions = rds.get_exclusions()

    if not data:
        return

    for ip, values in data.items():
        rules = rule_manager(role='attacker')

        if 'ports' not in values or len(values['ports']) <= 0:
            return

        for port in values['ports']:
            logger.info(f"Attacking Asset: {ip} on port: {port}")

            for rule in rules.values():
                rule_id = rule.rule

                """
                Check if the target is in exclusions list, if it is, skip.
                """
                if exclusions and rule_id in exclusions and ip in exclusions[rule_id]:
                    logger.debug(f"Skipping rule {rule_id} for target {ip} (excluded)")
                    continue

                """
                Only run rules that are in the allowed_aggressive config level.
                """
                if conf['config']['allow_aggressive'] < rule.intensity:
                    logger.debug(f"Skipping rule {rule_id} for target {ip} (high intensity: {rule.intensity})")
                    continue

                thread = threading.Thread(target=rule.check_rule, args=(ip, port, values, conf))
                thread.start()


def attacker():
    count = 0
    logger.info('Attacker process started')

    while True:
        conf = rds.get_scan_config()

        if not conf:
            logger.debug('Attacker process waiting for configuration...')
            time.sleep(10)
            continue

        run_rules(conf)
        count += 1

        if count == conf['config']['scan_opts']['parallel_attack']:
            time.sleep(30)
            count = 0
            active_count = threading.active_count()

            if active_count > 50:
                logger.debug(f'Sleeping for 30 seconds to control threads (Threads: {active_count})')
                time.sleep(30)
