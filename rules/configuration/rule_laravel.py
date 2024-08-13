from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage

class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_823E'
        self.rule_severity = 3
        self.rule_description = 'This rule checks for misconfigurations in Laravel'
        self.rule_confirm = 'Remote Server Misconfigured Laravel'
        self.rule_mitigation = (
            'Laravel has been misconfigured and may leak environment or log data. '
            'Use the Laravel Hardening Guidelines for reference: https://laravel.com/docs/7.x/configuration'
        )
        self.rule_details = ''
        
        self.rule_match_string = {
            '/storage/logs/laravel.log': {
                'app': 'LARAVEL_FRAMEWORK_LOG',
                'match': ['Stack trace', 'Did you mean one of these?', 'ConsoleOutput'],
                'title': 'Laravel Framework Log'
            },
            '/.env': {
                'app': 'LARAVEL_FRAMEWORK_ENV',
                'match': ['MIX_PUSHER_APP_KEY', 'BROADCAST_DRIVER'],
                'title': 'Laravel Framework Env File'
            },
            '/readme.md': {
                'app': 'LARAVEL_README',
                'match': ['Laravel'],
                'title': 'Laravel README File'
            },
            '/public/index.php': {
                'app': 'LARAVEL_PUBLIC_INDEX',
                'match': ['Laravel'],
                'title': 'Laravel Public Index File'
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
                self.rule_details = f'Laravel Misconfiguration - {title} at {response.url}'
                domain = scan_parser.get_domain()
                vuln_dict = self.get_vuln_dict(ip, port, domain)
                rds.store_vuln(vuln_dict)
