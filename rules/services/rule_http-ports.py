from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from db.db_ports import http_ports, https_ports


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_ZGZA'
        self.rule_severity = 1
        self.rule_description = 'This rule checks for open HTTP/HTTPS Ports'
        self.rule_confirm = 'Remote Server Exposes HTTP/HTTPS Port(s)'
        self.rule_details = ''
        self.rule_mitigation = (
            'Bind all possible network services to localhost, and configure '
            'only those which require remote clients on an external interface.'
        )
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        if port in http_ports:
            port_type = 'HTTP'
        elif port in https_ports:
            port_type = 'HTTPS'
        else:
            return

        domain = ScanParser(port, values).get_domain()
        self.rule_details = f'Server is listening on remote port: {port} ({port_type})'
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
