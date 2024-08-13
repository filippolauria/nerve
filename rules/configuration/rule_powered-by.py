from core.redis import rds
from core.triage import Triage
from core.parser import ScanParser

class Rule:
    def __init__(self):
        self.rule = 'CFG_BZLS'
        self.rule_severity = 0
        self.rule_description = "This rule checks if the Server's Response Headers Reveals Platform Version"
        self.rule_confirm = 'Identified Powered By Headers'
        self.rule_details = ''
        self.rule_mitigation = (
            'Disable Version Advertisement in the Web Server Configuration.\n'
            'In IIS: https://stackoverflow.com/questions/3374831/in-iis-can-i-safely-remove-the-x-powered-by-asp-net-header\n'
            'In ASP.NET: https://doc.sitecore.com/developers/90/platform-administration-and-architecture/en/remove-header-information-from-responses-sent-by-your-website.html'
        )
        self.intensity = 1

        self.powered_by_headers = ['X-AspNet-Version', 'X-Generator', 'X-Powered-By', 'X-Redirect-By', 'X-AspNetMvc-Version',
                                   'X-Powered-By-Plesk', 'X-Powered-By-Node', 'X-Drupal-Cache', 'X-Symfony-Cache']

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)
        module = scan_parser.get_module().strip().lower()

        if 'http' not in module:
            return

        triage = Triage()
        response = triage.http_request(ip, port)

        if response is None:
            return

        for powered_by_header in self.powered_by_headers:
            result = triage.string_in_headers(response, powered_by_header)
            if not result:
                continue

            self.rule_details = f"Server response contains '{powered_by_header}' header"

            rds.store_vuln({
                'ip': ip,
                'port': port,
                'domain': scan_parser.get_domain(),
                'rule_id': self.rule,
                'rule_sev': self.rule_severity,
                'rule_desc': self.rule_description,
                'rule_confirm': self.rule_confirm,
                'rule_details': self.rule_details,
                'rule_mitigation': self.rule_mitigation
            })

        return
