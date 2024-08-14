from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from db.db_ports import smb_ports


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_Z115'
        self.rule_severity = 3
        self.rule_description = 'This rule checks for open SMB ports'
        self.rule_confirm = 'Remote Server Exposes SMB Port(s)'
        self.rule_details = ''
        self.rule_mitigation = (
            "Bind all network services to localhost by default, and only configure those that "
            "require remote access on external interfaces."
        )
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        if port not in smb_ports:
            return

        self.rule_details = f"Server is listening on remote port: {port} ({smb_ports[port]})"
        domain = ScanParser(port, values).get_domain()
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
