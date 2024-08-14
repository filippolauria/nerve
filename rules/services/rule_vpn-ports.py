from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from db.db_ports import vpn_ports


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_ZII2'
        self.rule_severity = 2
        self.rule_description = 'This rule detects the exposure of standard VPN ports.'
        self.rule_confirm = 'Exposed VPN Port Detected'
        self.rule_details = ''
        self.rule_mitigation = (
            'Bind all non-essential network services to localhost. '
            'Configure only those services that require remote access on external interfaces and restrict access to trusted IP addresses.'
        )
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        if port not in vpn_ports:
            return

        self.rule_details = f'Server is exposing a VPN service on port: {port} ({vpn_ports[port]})'
        domain = ScanParser(port, values).get_domain()
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
