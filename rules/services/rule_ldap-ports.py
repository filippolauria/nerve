from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from db.db_ports import ldap_ports


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'SVC_222E'
        self.rule_severity = 3
        self.rule_description = 'This rule checks for open LDAP Ports'
        self.rule_confirm = 'Remote Server Exposes LDAP Port(s)'
        self.rule_details = ''
        self.rule_mitigation = (
            'Bind all possible network services to localhost, '
            'and allow those which require remote clients to connect. '
            '[!] {info}'
        )
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        if port not in ldap_ports:
            return

        domain = ScanParser(port, values).get_domain()
        self.rule_details = 'Server is listening on remote port:{} ({})'.format(port, ldap_ports[port])
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
