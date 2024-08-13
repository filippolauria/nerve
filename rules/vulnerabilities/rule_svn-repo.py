from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage
from db.db_paths import COMMON_WEB_PATHS


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'VLN_BLKK'
        self.rule_severity = 4
        self.rule_description = 'This rule checks for open SVN Repositories'
        self.rule_confirm = 'SVN Repository Found'
        self.rule_details = ''
        self.rule_mitigation = '''Block remote access to the Subversion repository.'''
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()

        for uri in COMMON_WEB_PATHS:
            response = triage.http_request(ip, port, uri=f"{uri}/.svn/text-base")
            if not response or 'Index of /' not in response.text:
                continue

            self.rule_details = f'Identified a SVN repository at {response.url}'
            domain = scan_parser.get_domain()
            vuln_dict = self.get_vuln_dict(ip, port, domain)
            rds.store_vuln(vuln_dict)
