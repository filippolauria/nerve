from core.redis import rds
from core.parser import ScanParser, Helper
from db.db_ports import known_ports_numbers


class Rule:
    def __init__(self):
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
        if port not in known_ports_numbers:
            return

        helper = Helper()
        translated_port = helper.port_translate(port)
        self.rule_details = f"Server is listening on remote port: {port} ({translated_port})"

        domain = ScanParser(port, values).get_domain()

        rds.store_vuln({
            'ip': ip,
            'port': port,
            'domain': domain,
            'rule_id': self.rule,
            'rule_sev': self.rule_severity,
            'rule_desc': self.rule_description,
            'rule_confirm': self.rule_confirm,
            'rule_details': self.rule_details,
            'rule_mitigation': self.rule_mitigation
        })

        return
