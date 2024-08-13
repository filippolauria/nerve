from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage
from db.db_paths import COMMON_LOGIN_PATHS


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_D2A9'
        self.rule_severity = 2
        self.rule_description = 'This rule checks if a Web Server has Basic Authentication enabled'
        self.rule_confirm = 'Basic Authentication is Configured'
        self.rule_mitigation = (
            'Basic authentication is a simple authentication scheme built into the HTTP protocol. '
            'The client sends HTTP requests with the Authorization header that contains the word Basic followed by a '
            'space and a base64-encoded string username:password. Basic Authentication does not have brute force protection '
            'mechanisms, and may potentially be a target for attackers.'
        )
        self.intensity = 2

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)
        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        domain = scan_parser.get_domain()

        for uri in COMMON_LOGIN_PATHS:
            response = triage.http_request(ip, port, uri=uri, normalize_headers=True)
            if (
                not response
                or response.status_code != 401
                or not response.normalized_headers.get('www-authenticate', '').lower().startswith('basic')
            ):
                continue

            self.rule_details = f'{self.rule_confirm} at {response.url}'
            vuln_dict = self.get_vuln_dict(ip, port, domain)
            rds.store_vuln(vuln_dict)
