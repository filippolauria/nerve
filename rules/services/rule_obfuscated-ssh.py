from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_21BV'
        self.rule_severity = 1
        self.rule_description = (
            'This rule checks for SSH services running on non-standard ports.'
        )
        self.rule_mitigation = (
            "Running SSH on non-standard ports offers minimal security benefits as attackers can easily identify the service.\n"
            "While changing the default port (22) does not hurt, it is crucial to enforce "
            "key-based authentication and restrict SSH access to trusted IP addresses only.\n"
        )
        self.rule_confirm = 'Remote server is running SSH on a non-standard port.'
        self.rule_details = ''
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if port != 22 and (scan_parser.is_module('ssh') or scan_parser.is_product('ssh')):
            self.rule_details = f"Server is running SSH on non-standard port: {port}"
            domain = scan_parser.get_domain()
            vuln_dict = self.get_vuln_dict(ip, port, domain)
            rds.store_vuln(vuln_dict)
