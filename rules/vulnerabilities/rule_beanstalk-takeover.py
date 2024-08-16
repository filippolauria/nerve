import dns.resolver

from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'VLN_ZZ13'
        self.rule_severity = 3
        self.rule_description = 'This rule checks for Beanstalk DNS Takeovers'
        self.rule_confirm = 'DNS Entry allows takeover of Beanstalk server'
        self.rule_details = ''
        self.rule_mitigation = 'Verify the DNS is in use, remove the record if unnecessary.'
        self.intensity = 1

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        domain = scan_parser.get_domain()

        if not domain:
            return

        try:
            for resolved in dns.resolver.query(domain, 'CNAME'):
                resolved_str = str(resolved).lower()
                if 'elasticbeanstalk.com' in resolved_str:
                    try:
                        dns.resolver.query(resolved_str)
                    except dns.resolver.NXDOMAIN:
                        self.rule_details = f'Beanstalk DNS Takeover at {domain} ({resolved_str})'
                        vuln_dict = self.get_vuln_dict(ip, port, domain)
                        rds.store_vuln(vuln_dict)
                        return
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return
