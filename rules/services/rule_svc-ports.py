from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from db.db_ports import svc_ports


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_F88A'
        self.rule_severity = 3
        self.rule_description = 'This rule identifies open service ports'
        self.rule_confirm = 'Exposed Service Port'
        self.rule_details = ''
        self.rule_mitigation = (
            "Bind all network services to localhost by default, and configure only those services "
            "that require remote access on external interfaces."
        )
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        if port not in svc_ports:
            return

        self.rule_details = f"Server is listening on remote port: {port} ({svc_ports[port]})"
        domain = ScanParser(port, values).get_domain()
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
