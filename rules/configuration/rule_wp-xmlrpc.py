from core.parser import ScanParser
from core.redis import rds
from core.triage import Triage

class Rule:
    def __init__(self):
        self.rule = 'CFG_B3AB'
        self.rule_severity = 1
        self.rule_description = (
            'This rule checks for XML-RPC Enabled interfaces in Wordpress'
        )
        self.rule_confirm = 'Remote Server supports XML-RPC'
        self.rule_mitigation = (
            'Wordpress is configured with XML-RPC. XML-RPC can be used to cause '
            'Denial of Service and User Enumeration on a Wordpress server.\n'
            'It is recommended to disable this interface if it is not utilized.\n'
            'Refer to the following article for more information on XML RPC Attacks: '
            'https://kinsta.com/blog/xmlrpc-php/'
        )
        self.rule_details = ''
        self.intensity = 1

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)
        module = scan_parser.get_module().strip().lower()

        if 'http' not in module:
            return

        # Prepare the base information to store
        object_to_store = {
            'ip': ip,
            'port': port,
            'domain': scan_parser.get_domain(),
            'rule_id': self.rule,
            'rule_sev': self.rule_severity,
            'rule_desc': self.rule_description,
            'rule_confirm': self.rule_confirm,
            'rule_details': '',
            'rule_mitigation': self.rule_mitigation
        }

        triage = Triage()

        # Check for GET request
        response = triage.http_request(ip, port, uri='/xmlrpc.php')
        if response and response.status_code == 405:
            object_to_store['rule_details'] = (
                'The server responded to a GET request at /xmlrpc.php with HTTP status code 405. '
                'This indicates that the XML-RPC endpoint is present but disallows GET requests, '
                'which is typical behavior but does not confirm if XML-RPC is fully disabled or secured.'
            )
            rds.store_vuln(object_to_store)
            return

        # Check for POST request
        response = triage.http_request(ip, port, uri='/xmlrpc.php', method='POST', data='<methodCall><methodName>system.listMethods</methodName></methodCall>')
        if response and response.status_code == 200:
            if '<methodResponse>' in response.text:
                object_to_store['rule_details'] = (
                    'The server is responding to POST requests at /xmlrpc.php with a valid XML-RPC response. '
                    'This suggests that XML-RPC is enabled and operational, which could potentially be used for '
                    'Denial of Service (DoS) attacks or unauthorized access. It is recommended to disable XML-RPC '
                    'if not in use.'
                )
                rds.store_vuln(object_to_store)

        return
