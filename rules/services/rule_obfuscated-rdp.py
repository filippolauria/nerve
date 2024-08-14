from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from db.db_ports import rdp_ports


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_2125'
        self.rule_severity = 1
        self.rule_description = (
            'This rule checks for Remote Desktop (RDP) services running on non-standard ports.'
        )
        self.rule_mitigation = (
            "Running Remote Desktop on non-standard ports provides minimal security benefits "
            "as attackers can still easily detect the service.\n"
            "While changing the default port (3389) does not inherently harm security, "
            "consider disabling Remote Desktop (RDP) if not needed, "
            "or restrict access to the service to trusted IP addresses only.\n"
        )
        self.rule_confirm = 'Remote server is running Remote Desktop (RDP) on a non-standard port.'
        self.rule_details = ''
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if port not in rdp_ports and (scan_parser.is_module('ms-wbt-server') or scan_parser.is_product('ms-wbt-server')):
            domain = scan_parser.get_domain()
            self.rule_details = f"Server is running Remote Desktop (RDP) on non-standard port: {port}"
            vuln_dict = self.get_vuln_dict(ip, port, domain)
            rds.store_vuln(vuln_dict)
