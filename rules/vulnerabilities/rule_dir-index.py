from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage
from db.db_paths import COMMON_WEB_PATHS


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'VLN_Z013'
        self.rule_severity = 4
        self.rule_description = 'This rule checks for Open Directories via Directory Indexing'
        self.rule_confirm = 'Remote Server has Directory Indexing Enabled'
        self.rule_details = ''
        self.rule_mitigation = (
            'Disable Directory Indexing on the server. '
            'Directory Indexing can allow access to files on the server to untrusted sources.'
        )
        self.intensity = 3
        self.matches = ['C=N;O=D', 'Index of /', ]

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()

        for uri in COMMON_WEB_PATHS:
            response = triage.http_request(ip, port, uri=uri)
            if not response or not self.check_match(response, self.matches):
                continue

            self.rule_details = f'Identified an Open Directory at {response.url}'
            domain = scan_parser.get_domain()
            vuln_dict = self.get_vuln_dict(ip, port, domain)
            rds.store_vuln(vuln_dict)
