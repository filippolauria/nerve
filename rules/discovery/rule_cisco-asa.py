from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage

class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'DSC_FFEE'
        self.rule_severity = 1
        self.rule_description = 'This rule checks for the exposure of Cisco ASA Panels'
        self.rule_confirm = 'Identified a Cisco ASA Panel'
        self.rule_mitigation = (
            'Identify whether the application in question is supposed to be exposed to the network.'
        )
        self.rule_details = ''

        self.common_login_match = ['<title>SSL VPN Service</title>', 'Cisco ASA']
        self.rule_match_string = {
          '/+CSCOE+/logon.html': {
              'app': 'CISCO_ASA',
              'match': self.common_login_match,
              'title': 'Cisco ASA'
          },
          '/+CSCOE+/login.htm': {
              'app': 'CISCO_ASA',
              'match': self.common_login_match,
              'title': 'Cisco ASA Login'
          },
          '/+CSCOE+/admin.html': {
              'app': 'CISCO_ASA',
              'match': ['<title>Adaptive Security Appliance</title>', 'Cisco Secure Firewall'],
              'title': 'Cisco ASA Admin'
          },
          '/+CSCOE+/index.html': {
              'app': 'CISCO_ASA',
              'match': ['<title>Adaptive Security Appliance</title>', 'Cisco ASA SSL VPN'],
              'title': 'Cisco ASA Index'
          },
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
