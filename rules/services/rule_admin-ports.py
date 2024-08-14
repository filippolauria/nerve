from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from db.db_ports import admin_ports


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_6509'
        self.rule_severity = 3
        self.rule_description = 'This rule checks for open Remote Management Ports'
        self.rule_mitigation = (
            'Bind all possible services to localhost, and confirm only those '
            'which require remote clients are allowed remotely.'
        )
        self.rule_confirm = 'Remote Server Exposes Administration Port(s)'
        self.rule_details = ''
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        if port not in admin_ports:
            return

        domain = ScanParser(port, values).get_domain()
        self.rule_details = f'Server is listening on remote port: {port} ({admin_ports[port]})'
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
