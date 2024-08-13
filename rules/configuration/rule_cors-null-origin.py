from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage

class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_32A0'
        self.rule_severity = 1
        self.rule_description = 'This rule checks if Cross Origin Resource Sharing policy trusts null origins'
        self.rule_confirm = 'CORS Policy Allows Null Origins'
        self.rule_mitigation = (
            'Consider hardening your Cross Origin Resource Sharing Policy to define specific Origins. '
            'More information can be found here: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'
        )
        self.rule_details = ''
        self.intensity = 1

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)
        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        domain = scan_parser.get_domain()
        target = domain if domain else ip
        headers = {'Origin': 'null'}
        
        response = triage.http_request(target, port, headers=headers, normalize_headers=True)

        if not response or response.normalized_headers.get('access-control-allow-origin', '').lower() != 'null':
            return

        self.rule_details = 'Remote Server accepted a NULL origin. Header used: "Origin: null"'
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
