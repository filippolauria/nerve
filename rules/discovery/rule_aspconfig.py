from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage

class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'DSC_GEG2'
        self.rule_severity = 2
        self.rule_description = 'This rule checks for the exposure of ASP.NET configurations'
        self.rule_confirm = 'Identified an ASP.NET Config'
        self.rule_mitigation = (
            'Identify whether the configuration file is supposed to be exposed to the network.'
        )
        self.rule_match_string = {
            '/web.config': {
                'app': 'ASPNET_CONFIG',
                'match': ['system.webServer'],
                'title': 'ASP.NET Config'
            }
        }
        self.intensity = 1

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)
        if not scan_parser.is_module('http'):
            return

        triage = Triage()

        for uri, match_values in self.rule_match_string.items():
            response = triage.http_request(ip, port, uri=uri)

            if not response:
                continue

            if self.check_match(response, match_values['match']):
                title = match_values['title']
                self.rule_details = f'Exposed {title} at {response.url}'
                domain = scan_parser.get_domain()
                vuln_dict = self.get_vuln_dict(ip, port, domain)
                rds.store_vuln(vuln_dict)
                return
