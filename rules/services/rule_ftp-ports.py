from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from db.db_ports import ftp_ports


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_C74A'
        self.rule_severity = 3
        self.rule_description = 'This rule checks for open FTP ports.'
        self.rule_confirm = 'Remote server exposes FTP port(s).'
        self.rule_details = ''
        self.rule_mitigation = (
            'At a minimum, ensure FTP is secured with SSL, '
            'and only allow trusted clients to connect over the network.'
        )
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        if port not in ftp_ports:
            return

        domain = ScanParser(port, values).get_domain()
        self.rule_details = f'Server is listening on remote port:{port} ({ftp_ports[port]})'
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
