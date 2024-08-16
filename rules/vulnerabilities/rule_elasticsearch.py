from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'VLN_77D7'
        self.rule_severity = 2
        self.rule_description = 'This rule checks for Open Elasticsearch instances'
        self.rule_confirm = 'Identified an open Elasticsearch'
        self.rule_details = ''
        self.rule_mitigation = (
            'Identify whether ElasticSearch should allow access to untrusted clients. '
            'https://www.elastic.co/guide/en/elasticsearch/reference/current/configuring-security.html'
        )
        self.rule_match_string = {
            '/_cat/indices?v': {
                'app': 'ELASTICSEARCH1',
                'match': ['"took":'],
                'title': 'Elastic Search'
            },
            '/_all/_search': {
                'app': 'ELASTICSEARCH2',
                'match': ['"took":'],
                'title': 'Elastic Search'
            },
        }
        self.intensity = 3

    def check_rule(self, ip, port, values, conf):
        if port != 9200 or port != 9300:
            return

        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        for uri, values in self.rule_match_string.items():
            response = triage.http_request(ip, port, uri=uri)

            if not response:
                continue

            if self.check_match(response, values['match']):
                title = values['title']
                self.rule_details = f'Exposed {title} at {response}'
                domain = scan_parser.get_domain()
                vuln_dict = self.get_vuln_dict(ip, port, domain)
                rds.store_vuln(vuln_dict)
                return
