import config
import pickle
from redis import ConnectionPool, Redis, RedisError
import sys
import threading

from core.logging import logger
from core.utils import Utils


class RedisManager:
    def __init__(self):
        self.utils = Utils()
        self.r = None
        try:
            # Configura un pool di connessione condiviso
            self.conn_pool = ConnectionPool(
                host=config.RDS_HOST,
                port=config.RDS_PORT,
                password=config.RDS_PASSW,
                db=0,
                socket_timeout=5
            )
            # Utilizza il pool di connessione configurato
            self.r = Redis(connection_pool=self.conn_pool)
        except RedisError as e:
            logger.error(f'Redis connection error: {e}')
            sys.exit(1)

    def store(self, key, value):
        return self.r.set(key, value)

    def store_json(self, key, value):
        if key and value:
            try:
                return self.r.set(key, pickle.dumps(value))
            except pickle.PicklingError as e:
                logger.error(f'Error pickling data: {e}')
        return False

    def store_topology(self, host):
        self.r.sadd("sess_topology", host)

    def get_slack_settings(self):
        return self.r.get('p_settings_slack')

    def get_email_settings(self):
        settings = self.r.get('p_settings_email')
        return pickle.loads(settings) if settings else None

    def store_vuln(self, v):
        key_hash = 'vuln_' + self.utils.hash_sha1(f"{v['ip']}{v['port']}{v['rule_id']}{v['rule_details']}")
        if self.r.setnx(key_hash, pickle.dumps(v)):
            logger.info('Vulnerability detected')

    def store_by_prefix(self, prefix, key, value):
        return self.store_json(f'{prefix}{key}', value)

    def store_sca(self, key, value):
        self.store_by_prefix('sca_', key, value)

    def store_inv(self, key, value):
        self.store_by_prefix('inv_', key, value)

    def store_sch(self, value):
        self.store(f'sch_{value}', value)

    def get_ips_to_scan(self, limit):
        data = {}
        for count, key in enumerate(self.r.scan_iter(match="sch_*", count=100), 1):
            value = self.r.get(key)
            if not value:
                self.r.delete(key)
                continue

            ip = key.decode('utf-8').split('_', 1)[1]
            data[ip] = {}
            self.r.delete(key)

            if count == limit:
                break

        return data

    def get_scan_data(self):
        kv = {}
        for ip_key in self.r.scan_iter(match="sca_*", count=100):
            data = self.r.get(ip_key)
            if data:
                try:
                    result = pickle.loads(data)
                    if result:
                        ip = ip_key.decode('utf-8').split('_', 1)[1]
                        kv[ip] = result
                        self.r.delete(ip_key)
                except pickle.UnpicklingError as e:
                    logger.error(f'Error unpickling data: {e}')
                    logger.debug(f'IP Key: {ip_key}')

        return kv

    def get_vuln_data(self):
        kv = {}
        for ip_key in self.r.scan_iter(match="vuln_*", count=100):
            data = self.r.get(ip_key)
            if data:
                try:
                    kv[ip_key.decode('utf-8')] = pickle.loads(data)
                except pickle.UnpicklingError as e:
                    logger.error(f'Error unpickling data: {e}')
        return kv

    def get_vuln_by_id(self, alert_id):
        vuln = self.r.get(alert_id)
        return pickle.loads(vuln) if vuln else None

    def get_inventory_data(self):
        kv = {}
        for ip_key in self.r.scan_iter(match="inv_*", count=100):
            data = self.r.get(ip_key)
            if data:
                try:
                    kv[ip_key.decode('utf-8')] = pickle.loads(data)
                except pickle.UnpicklingError as e:
                    logger.error(f'Error unpickling data: {e}')
        return kv

    def get_topology(self):
        return self.r.smembers("sess_topology")

    def get_scan_config(self):
        cfg = self.r.get('sess_config')
        return pickle.loads(cfg) if cfg else {}

    def get_scan_progress(self):
        return sum(1 for _ in self.r.scan_iter(match="sch_*", count=100))

    def get_exclusions(self):
        exc = self.r.get('p_rule-exclusions')
        return pickle.loads(exc) if exc else {}

    def get_last_scan(self):
        return self.r.get('p_last-scan')

    def get_scan_count(self):
        return self.r.get('p_scan-count')

    def is_attack_active(self):
        return any(i.name.startswith('rule_') for i in threading.enumerate())

    def is_scan_active(self):
        return bool(self.get_scan_progress())

    def is_session_active(self):
        return self.is_scan_active() or self.is_attack_active()

    def get_session_state(self):
        state = self.r.get('sess_state')
        return state.decode('utf-8').strip().lower() if state else ''

    def create_session(self):
        self.store('sess_state', 'created')
        self.r.incr('p_scan-count')
        self.r.set('p_last-scan', self.utils.get_datetime())

    def start_session(self):
        logger.info('Starting a new session...')
        self.store('sess_state', 'running')

    def end_session(self):
        logger.info('The session has ended.')
        self.store('sess_state', 'completed')

    def clear_session(self):
        keys_to_delete = []
        for prefix in ('vuln', 'sca', 'sch', 'inv'):
            keys_to_delete.extend(self.r.scan_iter(match=f"{prefix}_*", count=100))

        if keys_to_delete:
            self.r.delete(*keys_to_delete)

        self.r.delete('sess_topology', 'sess_config', 'sess_state')
        self.utils.clear_log()

    def is_ip_blocked(self, ip):
        key = f'logon_attempt-{ip}'
        attempts = self.r.get(key)
        if attempts and int(attempts) >= config.MAX_LOGIN_ATTEMPTS:
            return True
        else:
            self.r.set(key, 1, ex=300)
        return False

    def log_attempt(self, ip):
        self.r.incr(f'logon_attempt-{ip}')

    def queue_empty(self):
        return not self.r.dbsize()

    def db_size(self):
        return self.r.dbsize()

    def initialize(self):
        self.clear_session()
        self.r.mset({'p_scan-count': 0, 'p_last-scan': 'N/A'})

    def flushdb(self):
        self.r.flushdb()

    def delete(self, key):
        self.r.delete(key)


rds = RedisManager()
