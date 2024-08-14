from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_2993'
        self.rule_severity = 1
        self.rule_description = 'This rule checks for Telnet services running on non-standard ports.'
        self.rule_mitigation = (
            "Running Telnet on non-standard ports provides minimal security as attackers can still easily detect the service.\n"
            "While changing the default port (23) does not inherently harm security, consider disabling Telnet if not needed, "
            "or restrict access to the service to trusted IP addresses only."
        )
        self.rule_confirm = 'Remote server is running Telnet on a non-standard port.'
        self.rule_details = ''
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if port != 23 and (scan_parser.is_module('telnet') or scan_parser.is_product('telnet')):
            domain = scan_parser.get_domain()
            self.rule_details = f"Server is running Telnet on non-standard port: {port}"
            vuln_dict = self.get_vuln_dict(ip, port, domain)
            rds.store_vuln(vuln_dict)
