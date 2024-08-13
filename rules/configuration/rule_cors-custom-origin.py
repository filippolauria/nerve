import random
import string

from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_DZ19'
        self.rule_severity = 1
        self.rule_description = 'This rule checks if Cross Origin Resource Sharing policy trusts arbitrary origins'
        self.rule_confirm = 'CORS Allows Arbitrary Origins'
        self.rule_mitigation = (
            'Consider hardening your Cross Origin Resource Sharing Policy to define specific Origins. '
            'More information can be found here: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'
        )
        self.rule_details = ''
        self.intensity = 1

    def randomize_origin(self, length=6):
        rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        return f'https://{rand_str}.com'

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)
        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        domain = scan_parser.get_domain()
        target = domain if domain else ip
        random_origin = self.randomize_origin()
        headers = {'Origin': random_origin}
        response = triage.http_request(target, port, headers=headers, normalize_headers=True)

        if not response or response.normalized_headers.get('access-control-allow-origin', '') != random_origin:
            return

        self.rule_details = f'Remote Server accepted a custom origin. Header used: "Origin: {random_origin}"'
        vuln_dict = self.get_vuln_dict(ip, port, domain)
        rds.store_vuln(vuln_dict)
