from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage
from db.db_paths import COMMON_WEB_PATHS


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'VLN_92F9'
        self.rule_severity = 4
        self.rule_description = 'This rule checks for open Git Repositories'
        self.rule_confirm = 'Remote Server Exposes Git Repository'
        self.rule_details = ''
        self.rule_mitigation = (
            'Git repository was found to be accessible. '
            'Configure the server in a way that makes git repository '
            'unreachable to untrusted clients'
        )
        self.intensity = 3

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()

        for uri in COMMON_WEB_PATHS:
            response = triage.http_request(ip, port, uri=f"{uri}/.git/HEAD")
            if not response or not response.text.startswith('ref:'):
                continue

            self.rule_details = f'Identified a git repository at {response.url}'
            domain = scan_parser.get_domain()
            vuln_dict = self.get_vuln_dict(ip, port, domain)
            rds.store_vuln(vuln_dict)
