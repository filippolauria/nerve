from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage

class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_DFFF'
        self.rule_severity = 1
        self.rule_description = 'This rule checks if Cross Origin Resource Sharing Headers support Wildcard Origins'
        self.rule_confirm = 'CORS Policy allows any domain'
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
        response = triage.http_request(target, port, normalize_headers=True)

        if not response or response.normalized_headers.get('access-control-allow-origin', '') != '*':
            return
        
        self.rule_details = 'Server responded with an HTTP Response Header of Access-Control-Allow-Origin: *'
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
