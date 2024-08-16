from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from db.db_ports import ftp_ports
from ftplib import FTP


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'VLN_242C'
        self.rule_severity = 4
        self.rule_description = 'This rule checks if FTP Server allows Anonymous Access'
        self.rule_details = ''
        self.rule_confirm = 'FTP Anonymous Access Allowed'
        self.rule_mitigation = (
            'FTP allows anonymous users access. '
            'Disable Anonymous FTP access if this is not a business requirement.'
        )
        self.rule_match_port = ftp_ports
        self.intensity = 0

    def check_rule(self, ip, port, values, conf):
        if port not in ftp_ports:
            return

        scan_parser = ScanParser(port, values)
        try:
            ftp = FTP(ip)
            response = ftp.login()

            if response and (
                '230' in response or
                'user logged in' in response or
                'successful' in response
            ):
                self.rule_details = 'FTP with Anonymous Access Enabled'
                domain = scan_parser.get_domain()
                vuln_dict = self.get_vuln_dict(ip, port, domain)
                rds.store_vuln(vuln_dict)
                return
        except Exception:
            pass
