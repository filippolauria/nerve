from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from db.db_ports import database_ports


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_0C15'
        self.rule_severity = 3
        self.rule_description = 'This rule checks for open Database Ports.'
        self.rule_confirm = 'Remote Server Exposes Database Port(s).'
        self.rule_details = ''
        self.rule_mitigation = (
            'Bind all possible database interfaces to localhost. '
            'If the database requires remote connections, allow only trusted source IP addresses.'
        )
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        if port not in database_ports:
            return

        domain = ScanParser(port, values).get_domain()
        self.rule_details = f'Server is listening on remote port: {port} ({database_ports[port]}).'
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
