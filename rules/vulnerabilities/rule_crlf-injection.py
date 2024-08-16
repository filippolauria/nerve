from core.redis import rds
from core.triage import Triage
from core.parser import ScanParser

from random import choices
from string import ascii_letters, digits


class Rule:
    def __init__(self):
        self.rule = 'VLN_ZPZB'
        self.rule_severity = 2
        self.rule_description = (
            'This rule checks for Carriage Return Line Feed Injections'
        )
        self.rule_confirm = (
            'Remote Server suffers from CRLF Injection / HTTP Response Splitting'
        )
        self.rule_details = ''
        self.rule_mitigation = (
            'Do not use CRLF characters in URL as HTTP stream\n'
            'Refer to the OWASP CRLF Injection article for more information: '
            'https://owasp.org/www-community/vulnerabilities/CRLF_Injection'
        )
        self.intensity = 1

    def random_cookie(self, length=6):
        return ''.join(choices(ascii_letters + digits, k=length))

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        cookie = self.random_cookie()
        payload = f"/%0d%0aset-cookie:foo={cookie}"
        response = triage.http_request(ip, port, follow_redirects=False, uri=payload, normalize_headers=True)

        if not response or cookie not in response.normalized_headers.get('set-cookie', ''):
            return

        self.rule_details = 'Identified CRLF Injection by inserting a Set-Cookie header'
        domain = scan_parser.get_domain()
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
