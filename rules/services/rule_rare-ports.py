from core.parser import Helper, ScanParser
from core.redis import rds
from core.rules import BaseRule
from db.db_ports import known_ports_numbers


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_0C1Z'
        self.rule_severity = 2
        self.rule_description = 'This rule checks for open Rare Ports'
        self.rule_confirm = 'Remote Server Exposes Rare Port(s)'
        self.rule_details = ''
        self.rule_mitigation = (
            'Bind all possible network services to localhost, and configure '
            'only those which require remote clients on an external interface.'
        )
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        if port in known_ports_numbers:
            return

        translated_port = Helper().port_translate(port)
        self.rule_details = f"Server is listening on remote port: {port} ({translated_port})"
        domain = ScanParser(port, values).get_domain()        
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
