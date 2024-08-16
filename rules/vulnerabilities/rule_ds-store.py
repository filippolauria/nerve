from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage
from core.parser import ScanParser
from db.db_paths import COMMON_WEB_PATHS
from os import remove
from struct import unpack_from
from tempfile import NamedTemporaryFile


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'VLN_AS91'
        self.rule_severity = 1
        self.rule_description = 'This rule checks for forgotten .DS_Store files'
        self.rule_confirm = '.DS_Store File Found'
        self.rule_details = ''
        self.rule_mitigation = (
            '''A .DS_Store file is a special MacOSX file which reveals the files within the same folder '''
            '''where it lives, and may indicate what other files exist on the webserver. '''
            '''This file occasionally gets pushed by mistake due to not adding it to .gitignore. '''
            '''Remove this file and add .DS_Store to .gitignore'''
        )
        self.rule_match_string = '.DS_Store'
        self.intensity = 2

    def is_file_ds_store(self, filename):
        offset_position = 0

        if len(filename) < 36 or len(filename) < offset_position + 2 * 4:
            return False

        value = filename[offset_position:offset_position + 2 * 4]

        magic1, magic2 = unpack_from(">II", value)

        return magic1 == 0x1 or magic2 == 0x42756431

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()

        for uri in COMMON_WEB_PATHS:
            response = triage.http_request(ip, port, uri=f'{uri}/.DS_Store')
            if not response:
                continue

            with NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(response.content)
                temp_file.flush()

                with open(temp_file.name, 'rb') as fd:
                    if self.is_file_ds_store(fd.read()):
                        self.rule_details = f'Identified .DS_Store file at {response.url}'
                        domain = scan_parser.get_domain()
                        vuln_dict = self.get_vuln_dict(ip, port, domain)
                        rds.store_vuln(vuln_dict)

            remove(temp_file.name)
