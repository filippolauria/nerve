from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage
from db.db_ports import ssh_ports


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_FOQW'
        self.rule_severity = 3
        self.rule_description = 'This rule checks if OpenSSH allows passwords as an accepted authentication mechanism'
        self.rule_confirm = 'Remote Server Supports SSH Passwords'
        self.rule_details = ''
        self.rule_mitigation = (
            'OpenSSH allows password authentication, this is considered bad security practice. '
            'SSH Key based authentication should be enabled on the server, and passwords should be disabled.'
        )
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('ssh') or port not in ssh_ports:
            return
    
        triage = Triage()
        
        output = triage.run_cmd(
            "ssh -o PreferredAuthentications=none -o ConnectTimeout=5 -o StrictHostKeyChecking=no"
            f" -o NoHostAuthenticationForLocalhost=yes -p {port} 'user@{ip}'"
        )

        if not output or 'password' not in str(output):
            return

        domain = scan_parser.get_domain()
        self.rule_details = 'Server accepts passwords as an authentication option'
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
