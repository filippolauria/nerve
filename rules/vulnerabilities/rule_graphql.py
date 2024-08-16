from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'VLN_FBQP'
        self.rule_severity = 2
        self.rule_description = 'This rule checks for open GraphQL Interfaces'
        self.rule_confirm = 'Exposed GraphQL Interface'
        self.rule_details = ''
        self.rule_mitigation = (
            'Restrict access to the GraphQL Interface to trusted sources or disable it completely if not in use.'
        )
        self.intensity = 1
        self.graphql_uris = ['/graphql', '/graphiql', ]

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        for uri in self.graphql_uris:
            response = triage.http_request(ip, port, uri=uri)

            if (
                response and
                response.status_code == 400 and
                'GET query missing.' in response.text
            ):
                self.rule_details = f'GraphQL Enabled on the Server at {response.url}'
                domain = scan_parser.get_domain()
                vuln_dict = self.get_vuln_dict(ip, port, domain)
                rds.store_vuln(vuln_dict)
                return
