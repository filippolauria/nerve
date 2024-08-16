from core.redis import rds
from core.triage import Triage
from core.parser import ScanParser
from random import choices
from string import ascii_letters, digits


class Rule:
    def __init__(self):
        self.rule = 'VLN_4SD5'
        self.rule_severity = 2
        self.rule_description = 'This rule checks for possible Host Header Injections'
        self.rule_confirm = 'Identified Host Header Injection'
        self.rule_details = ''
        self.rule_mitigation = (
            'Redirect only to allowed hosts, otherwise ignore the Host Header. '
            'This may not indicate an immediate problem, '
            'but could potentially become an issue if any URLs are being constructed using the Host header. '
            'Refer to the following Acunetix article for more information on Host Header Injections: '
            'https://www.acunetix.com/blog/articles/automated-detection-of-host-header-attacks'
        )
        self.intensity = 1

    def random_domain_name(self, length=10):
        return ''.join(choices(ascii_letters + digits, k=length)) + ".com"

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)
        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        random_host = self.random_domain_name()

        headers = {'X-Forwarded-Host': random_host, 'Host': random_host}
        response = triage.http_request(ip, port, follow_redirects=False, headers=headers, normalize_headers=True)

        if response and random_host in response.normalized_headers.get('location', ''):
            self.rule_details = (
                'Host header injection was possible via headers: '
                f'X-Forwarded-Host: {random_host} and/or Host: {random_host}'
            )
            domain = scan_parser.get_domain()
            vuln_dict = self.get_vuln_dict(ip, port, domain)
            rds.store_vuln(vuln_dict)
