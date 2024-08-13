from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_9B88'
        self.rule_severity = 3
        self.rule_description = 'This rule checks for misconfigurations in Spring Boot Actuator'
        self.rule_confirm = 'Spring Boot Actuator is misconfigured'
        self.rule_details = ''
        self.rule_mitigation = (
            'Server has a misconfigured Actuator, which is potentially leaking out sensitive data. '
            'Restrict access to the endpoint to trusted sources only.\n'
            'Refer to the following Spring Boot Actuator Hardening Guideline for more information: '
            'https://www.devglan.com/spring-security/securing-spring-boot-actuator-endpoints-with-spring-security'
        )

        dump_common_match = ['lineNumber', 'threadState', 'blockedTime', 'threadName']
        env_common_match = ['os.arch', 'java.vm.vendor', 'java.runtime.name', 'java.library.path']
        health_common_match = ['"diskSpace":']
        metrics_common_match = ['"mem":', '"heap":']
        info_common_match = ['"app":', '"version":']

        self.rule_match_string = {
            '/admin/dump': {
                'app': 'SPRING_BOOT_ACTUATOR_DUMP',
                'match': dump_common_match,
                'title': 'Spring Boot Actuator'
            },
            '/dump': {
                'app': 'SPRING_BOOT_ACTUATOR_DUMP',
                'match': dump_common_match,
                'title': 'Spring Boot Actuator'
            },
            '/admin/env.json': {
                'app': 'SPRING_BOOT_ACTUATOR_ENV',
                'match': env_common_match,
                'title': 'Spring Boot Actuator'
            },
            '/actuator/env': {
                'app': 'SPRING_BOOT_ACTUATOR_ENV',
                'match': env_common_match,
                'title': 'Spring Boot Actuator'
            },
            '/env.json': {
                'app': 'SPRING_BOOT_ACTUATOR_ENV',
                'match': env_common_match,
                'title': 'Spring Boot Actuator'
            },
            '/env': {
                'app': 'SPRING_BOOT_ACTUATOR_ENV',
                'match': env_common_match,
                'title': 'Spring Boot Actuator'
            },
            '/actuator/health': {
                'app': 'ACTUATOR_HEALTH',
                'match': health_common_match,
                'title': 'Actuator Health'
            },
            '/health': {
                'app': 'ACTUATOR_HEALTH',
                'match': health_common_match,
                'title': 'Actuator Health'
            },
            '/actuator/metrics': {
                'app': 'ACTUATOR_METRICS',
                'match': metrics_common_match,
                'title': 'Actuator Metrics'
            },
            '/metrics': {
                'app': 'ACTUATOR_METRICS',
                'match': metrics_common_match,
                'title': 'Actuator Metrics'
            },
            '/actuator/info': {
                'app': 'ACTUATOR_INFO',
                'match': info_common_match,
                'title': 'Actuator Info'
            },
            '/info': {
                'app': 'ACTUATOR_INFO',
                'match': info_common_match,
                'title': 'Actuator Info'
            },
        }

        self.intensity = 3

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        domain = scan_parser.get_domain()

        for uri, values in self.rule_match_string.items():
            response = triage.http_request(ip, port, uri=uri)

            if not response:
                continue

            matches = values['match']
            title = values['title']

            if self.check_match(response, matches):
                self.rule_details = f'Exposed {title} at {response.url}'
                vuln_dict = self.get_vuln_dict(ip, port, domain)
                rds.store_vuln(vuln_dict)
