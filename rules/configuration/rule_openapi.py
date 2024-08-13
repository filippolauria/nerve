from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_ZEGE'
        self.rule_severity = 2
        self.rule_description = 'This rule checks for accessible Open API (Swagger) Documentation'
        self.rule_confirm = 'Remote Server is exposing Swagger API'
        self.rule_details = ''
        self.rule_mitigation = (
            'Swagger API may have been incorrectly configured to allow access to untrusted clients. '
            'Check whether this can be restricted, as it may lead to attackers identifying your application endpoints.'
        )

        self.common_api_match = ['"swagger":"2.0"']
        self.common_ui_match = ['Swagger UI', '"swagger"']

        self.rule_match_string = {
            '/help': {
                'app': 'ASPNET_WEBAPI_HELP',
                'match': ['ASP.NET Web API Help Page'],
                'title': 'ASP.NET API Docs'
            },
            '/v2/api-docs': {
                'app': 'SWAGGER',
                'match': self.common_api_match,
                'title': 'REST API Documentation'
            },
            '/api-docs': {
                'app': 'SWAGGER',
                'match': self.common_api_match,
                'title': 'REST API Documentation'
            },
            '/swagger/index.html': {
                'app': 'SWAGGER_ALT1',
                'match': self.common_ui_match,
                'title': 'REST API Documentation'
            },
            '/swagger-ui.html': {
                'app': 'SWAGGER_ALT2',
                'match': self.common_ui_match,
                'title': 'REST API Documentation'
            },
            '/api/swagger-ui.html': {
                'app': 'SWAGGER_ALT3',
                'match': self.common_ui_match,
                'title': 'REST API Documentation'
            },
            '/api-docs/swagger.json': {
                'app': 'SWAGGER_ALT4',
                'match': self.common_ui_match,
                'title': 'REST API Documentation'
            },
            '/swagger.json': {
                'app': 'SWAGGER_ALT5',
                'match': self.common_ui_match,
                'title': 'REST API Documentation'
            },
            '/swagger/v1/swagger.json': {
                'app': 'SWAGGER_ALT6',
                'match': self.common_ui_match,
                'title': 'REST API Documentation'
            },
        }
        self.intensity = 3

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
                self.rule_details = f'Identified an exposed {values["title"]} at {response.url}'
                domain = scan_parser.get_domain()
                vuln_dict = self.get_vuln_dict(ip, port, domain)
                rds.store_vuln(vuln_dict)
