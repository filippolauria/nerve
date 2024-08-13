from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_ESTR'
        self.rule_severity = 4
        self.rule_description = 'This rule checks for NodeJS Server.js file exposures'
        self.rule_confirm = 'Remote NodeJS Server is leaking server.js'
        self.rule_details = ''
        self.rule_mitigation = (
            'NodeJS has been configured to serve server.js which may allow attackers access to backend code.'
        )
        self.intensity = 1

        # Match strings specific to Node.js server.js exposure
        self.rule_match_string = [
            "require('http')",
            "module.exports",
            "server.listen",
            "http-proxy-middleware",
            "const http =",        # Common for creating HTTP servers in Node.js
            "process.env",         # Environment variables are often accessed in Node.js
            "require('fs')",       # Node.js file system module
            "require('path')",     # Node.js path module
            "require('url')",      # Node.js URL module
            "require('net')",      # Node.js networking module
        ]

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        response = triage.http_request(ip, port, uri='/server.js', follow_redirects=False)

        if not response:
            return

        if self.check_match(response, self.rule_match_string):
            domain = scan_parser.get_domain()
            self.rule_details = f'Identified a NodeJS Leakage at {response.url}'
            vuln_dict = self.get_vuln_dict(ip, port, domain)
            rds.store_vuln(vuln_dict)
