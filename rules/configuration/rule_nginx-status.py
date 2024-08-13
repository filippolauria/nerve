from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_ECC8'
        self.rule_severity = 1
        self.rule_description = 'This rule checks for misconfigurations in Nginx'
        self.rule_confirm = 'Nginx Server is misconfigured'
        self.rule_details = ''
        self.rule_mitigation = (
            'Nginx is configured with default configurations, which exposes one or more status endpoints. '
            'Nginx status may unintentionally reveal information which should not be remotely accessible. '
            'The following article discusses the status module in-depth: '
            'http://nginx.org/en/docs/http/ngx_http_stub_status_module.html.'
        )

        self.rule_match_string = {
            '/status': {
                'app': 'NGINX_STATUS',
                'match': [
                    'Check upstream server',
                    'Nginx http upstream check status',
                    'Active connections',
                    'server accepts handled requests'
                ],
                'title': 'Nginx connections page'
            },
            '/nginx_status': {
                'app': 'NGINX_STATUS_PAGE',
                'match': [
                    'server accepts handled requests',
                    'Active connections',
                    'Reading: ',
                    'Writing: ',
                    'Waiting: '
                ],
                'title': 'Nginx Status Page',
            },
            '/static/resources/@': {
                'app': 'NGINX_INTERNAL_CONFIG',
                'match': [
                    'access_log',
                    'error_log',
                    'proxy_pass',
                    'add_header',
                    'location /',
                    'root ',
                    'server_name',
                    'listen '
                ],
                'title': 'Nginx Internal Config',
            },
            '/nginx.conf': {
                'app': 'NGINX_CONFIG_FILE',
                'match': [
                    'worker_processes',
                    'http {',
                    'server {',
                    'include /etc/nginx/',
                    'ssl_certificate',
                    'ssl_certificate_key'
                ],
                'title': 'Nginx Main Configuration File',
            },
        }
        self.intensity = 1

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()

        for uri, values in self.rule_match_string.items():
            response = triage.http_request(ip, port, uri=uri)
            if not response:
                continue

            if self.check_match(response, values['match']):
                self.rule_details = f'Nginx Misconfiguration - {values["title"]} at {response.url}'
                domain = scan_parser.get_domain()
                vuln_dict = self.get_vuln_dict(ip, port, domain)
                rds.store_vuln(vuln_dict)
