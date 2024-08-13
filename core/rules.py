from core.parser import ScanParser
from core.redis import rds
from core.triage import Triage


class BaseRule:
    def __init__(self):
        self.rule = ''
        self.rule_severity = 0
        self.rule_description = ''
        self.rule_confirm = ''
        self.rule_details = ''
        self.rule_mitigation = ''
        self.intensity = 0

    def get_vuln_dict(self, ip, port, domain):
        return {
            'ip': ip,
            'port': port,
            'domain': domain,
            'rule_id': self.rule,
            'rule_sev': self.rule_severity,
            'rule_desc': self.rule_description,
            'rule_confirm': self.rule_confirm,
            'rule_details': self.rule_details,
            'rule_mitigation': self.rule_mitigation
        }

    def check_match(self, response, matches):
        for match in matches:
            if match in response.text:
                return True

        return False


class BasicWebRule(BaseRule):
    def __init__(self, rid='', intensity=0, severity=0, description='', confirm='', details='', mitigation='', rule_match_string={}):
        super().__init__()
        self.rule = rid
        self.rule_severity = severity
        self.rule_description = description
        self.rule_confirm = confirm
        self.rule_details = details
        self.rule_mitigation = mitigation
        self.intensity = intensity
        self.rule_match_string = rule_match_string

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        domain = scan_parser.get_domain()

        if isinstance(self.rule_match_string, dict) and len(self.rule_match_string.keys()) > 0:

            for uri, values in self.rule_match_string.items():

                response = triage.http_request(ip, port, uri=uri)
                if not response:
                    continue

                if self.check_match(response, values['match']):
                    title = values['title']
                    self.rule_details += f' - {title} at {response.url}'
                    vuln_dict = self.get_vuln_dict(ip, port, domain)
                    rds.store_vuln(vuln_dict)
            return
