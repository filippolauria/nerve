from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_0391'
        self.rule_severity = 1
        self.rule_description = 'This rule checks for VNC services running on non-standard ports'
        self.rule_mitigation = (
            "VNC services running on non-standard ports are easy for attackers to discover.\n"
            "While changing the default ports (5800-5804, 5900-5904) does not inherently increase security, "
            "it is recommended to disable VNC if not needed or restrict access to trusted IP addresses only."
        )
        self.rule_confirm = 'Remote Server Exposes VNC on non-standard ports'
        self.rule_details = ''
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if (
            port not in range(5900, 5905) and
            port not in range(5800, 5805) and
            (
                scan_parser.is_module('vnc') or
                scan_parser.is_product('vnc') or
                scan_parser.is_module('X11') or
                scan_parser.is_product('X11')
            )
        ):
            domain = scan_parser.get_domain()
            self.rule_details = f"Server is running VNC on a non-standard port: {port}"
            vuln_dict = self.get_vuln_dict(ip, port, domain)
            rds.store_vuln(vuln_dict)
