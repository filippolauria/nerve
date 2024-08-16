from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage
from random import choices
from string import ascii_letters, digits


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'VLN_ZD10'
        self.rule_severity = 2
        self.rule_description = 'This rule checks for X-Forwarded-Host Injection'
        self.rule_confirm = 'Remote Server suffers from X-Forwarded-Host Injection'
        self.rule_details = ''
        self.rule_mitigation = (
            'Configure the server to not redirect based on arbitrary XFH headers provided by the user. '
            'Refer to the following OWASP article for more information: '
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection'
        )
        self.intensity = 1

    def random_xfh(self, length=6):
        rand_str = ''.join(choices(ascii_letters + digits, k=length))
        return f'www.{rand_str}.local'

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        domain = scan_parser.get_domain()
        target = domain if domain else ip
        custom_xfh = self.random_xfh()
        headers = {'X-Forwarded-Host': custom_xfh}
        response = triage.http_request(target, port, normalize_headers=True, follow_redirects=False, headers=headers)

        if not response or response.normalized_headers.get('location', '') != custom_xfh:
            return

        self.rule_details = f'Server Redirected to an Arbitrary Location ({custom_xfh})'
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
