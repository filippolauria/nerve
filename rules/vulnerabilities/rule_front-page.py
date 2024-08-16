from core.redis import rds
from core.triage import Triage
from core.parser import ScanParser


class Rule:
    def __init__(self):
        self.rule = 'VLN_65C8'
        self.rule_severity = 2
        self.rule_description = 'This rule checks for FrontPage configuration information disclosure'
        self.rule_confirm = 'FrontPage misconfiguration'
        self.rule_details = ''
        self.rule_mitigation = 'Ensure SharePoint is not anonymously accessible'
        self.intensity = 1

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        response = triage.http_request(ip, port, uri='/_vti_inf.html', normalize_headers=True)

        try:
            if not response or int(response.normalized_headers.get('content-length', 0)) != 247:
                return
        except ValueError:
            return

        self.rule_details = f'Exposed FrontPage at {response.url}'
        domain = scan_parser.get_domain()
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
