from bs4 import BeautifulSoup
from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage
from db.db_paths import COMMON_LOGIN_PATHS


class Rule(BaseRule):
    def __init__(self):
        self.rule = 'VLN_SKKF'
        self.rule_severity = 2
        self.rule_description = 'This rule checks for password forms over HTTP protocols'
        self.rule_confirm = 'Unencrypted Login Form'
        self.rule_details = ''
        self.rule_mitigation = (
            'Website accepts credentials via HTML Forms, however, '
            'it offers no encryptions and may allow attackers to intercept them.'
        )
        self.intensity = 1

    def contains_password_form(self, text):
        if not text:
            return False

        try:
            soup = BeautifulSoup(text, 'html.parser')
            inputs = soup.findAll('input')
            if not inputs:
                return False

            for i in inputs:
                if i.attrs.get('type') == 'password':
                    return True
        except Exception:
            pass

        return False

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        domain = scan_parser.get_domain()

        for uri in COMMON_LOGIN_PATHS:
            response = triage.http_request(ip, port, uri=uri)

            if (
                not response or
                not response.url.startswith('https://') or
                not self.contains_password_form(response.text)
            ):
                continue

            self.rule_details = f'Login Page over HTTP at {response.url}'
            vuln_dict = self.get_vuln_dict(ip, port, domain)
            rds.store_vuln(vuln_dict)
