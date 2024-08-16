from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage
from db.db_paths import COMMON_LOGIN_PATHS


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'VLN_FF00'
        self.rule_severity = 4
        self.rule_description = 'This rule checks for Open Wordpress Upload Directories'
        self.rule_confirm = 'Remote Wordpress has an Uploads Folder with Indexing Enabled'
        self.rule_details = ''
        self.rule_mitigation = '''Disable Directory Indexing on the Wordpress instance.'''
        self.intensity = 1

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()

        for uri in COMMON_LOGIN_PATHS:
            response = triage.http_request(ip, port, uri=f'{uri}/wp-content/uploads/')
            if response and 'Index of /wp-content/uploads' in response.text:
                self.rule_details = f'Found Uploads Directory at {response.url}'
                domain = scan_parser.get_domain()
                vuln_dict = self.get_vuln_dict(ip, port, domain)
                rds.store_vuln(vuln_dict)
                break
