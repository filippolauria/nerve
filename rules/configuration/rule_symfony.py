from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_SYMF'
        self.rule_severity = 3
        self.rule_description = 'This rule checks for misconfigurations in Symfony'
        self.rule_confirm = 'Remote Server Misconfigured Symfony'
        self.rule_mitigation = (
            'Symfony has been misconfigured and may leak environment or log data. '
            'Follow Symfony Security Best Practices: https://symfony.com/doc/current/security.html'
        )
        self.rule_details = ''
        self.rule_match_string = {
            '/var/log/symfony.log': {
                'app': 'SYMFONY_FRAMEWORK_LOG',
                'match': ['Symfony', 'An error occurred'],
                'title': 'Symfony Framework Log'
            },
            '/.env': {
                'app': 'SYMFONY_FRAMEWORK_ENV',
                'match': [
                    'APP_ENV',
                    'DATABASE_URL'
                ],
                'title': 'Symfony Framework Env File'
            },
            '/config/packages/dev/': {
                'app': 'SYMFONY_DEV_CONFIG',
                'match': ['debug'],
                'title': 'Symfony Dev Configuration Directory'
            },
            '/readme.md': {
                'app': 'SYMFONY_README',
                'match': ['Symfony'],
                'title': 'Symfony README File'
            },
            '/public/index.php': {
                'app': 'SYMFONY_PUBLIC_INDEX',
                'match': ['Symfony'],
                'title': 'Symfony Public Index File'
            }
        }
        self.intensity = 1

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)
        if not scan_parser.is_module('http'):
            return

        triage = Triage()

        for uri, match_values in self.rule_match_string.items():
            response = triage.http_request(ip, port, uri=uri)

            if response is None:
                continue

            if self.check_match(response, match_values['match']):
                title = match_values['title']
                self.rule_details = f'Symfony Misconfiguration - {title} at {response.url}'
                domain = scan_parser.get_domain()
                vuln_dict = self.get_vuln_dict(ip, port, domain)
                rds.store_vuln(vuln_dict)
