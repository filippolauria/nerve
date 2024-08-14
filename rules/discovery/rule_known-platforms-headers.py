from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'DSC_FB18'
        self.rule_severity = 1
        self.rule_description = 'This rule checks for the exposure of Known Platform based on response header signatures'
        self.rule_confirm = 'Identified a Known Platform via its Headers'
        self.rule_details = ''
        self.rule_mitigation = '''Identify whether the application in question is supposed to be exposed to the network.'''
        self.rule_match_string = {
            'Jenkins': {
                'app': 'JENKINS',
                'match': ['X-Jenkins', 'X-Hudson'],
                'title': 'Build Server'
            },
            'Artifactory': {
                'app': 'ARTIFACTORY',
                'match': ['X-Artifactory-Id', '/artifactory/webapp/'],
                'title': 'Software Artifacts server'
            },
            'Kubernetes': {
                'app': 'KUBERNETES',
                'match': ['kubernetes-master'],
                'title': 'Container Orchestration'
            },
            'Docker': {
                'app': 'DOCKER',
                'match': ['Server: Docker', 'Docker'],
                'title': 'Containers'
            },
            'etcd': {
                'app': 'ETCD',
                'match': ['etcd'],
                'title': 'K/V Storage'
            },
            'Grafana': {
                'app': 'GRAFANA',
                'match': ['grafana'],
                'title': 'Graph Platform'
            },
            'Prometheus': {
                'app': 'PROMETHEUS',
                'match': ['Prometheus'],
                'title': 'Monitoring System'
            },
            'Kibana': {
                'app': 'KIBANA',
                'match': ['kibana', 'kbn-name'],
                'title': 'Analytics'
            },
            'phpMyAdmin': {
                'app': 'PHPMYADMIN',
                'match': ['phpMyAdmin'],
                'title': 'MySQL Admin Panel'
            },
            'OpenNMS': {
                'app': 'OPENNMS',
                'match': ['opennms'],
                'title': 'Monitoring System'
            },
            'Observium': {
                'app': 'OBSERVIUM',
                'match': ['observium'],
                'title': 'Monitoring System'
            },
            'MongoDB': {
                'app': 'MONGODB',
                'match': ['MongoDB'],
                'title': 'Database'
            },
            'Zabbix': {
                'app': 'ZABBIX',
                'match': ['zabbix'],
                'title': 'Monitoring System'
            },
            'Weblogic': {
                'app': 'WEBLOGIC',
                'match': ['10.3.6.0.0', '12.1.3.0.0', '12.2.1.1.0', '12.2.1.2.0'],
                'title': 'Weblogic'
            },
            'Webmin': {
                'app': 'WEBMIN',
                'match': ['MiniServ'],
                'title': 'Webmin'
            },
            'Graylog': {
                'app': 'GRAYLOG',
                'match': ['X-Graylog-Node-ID'],
                'title': 'Graylog'
            },
            'SpringEureka': {
                'app': 'SPRING_EUREKA',
                'match': ['Instances currently registered with Eureka'],
                'title': 'Monitoring System'
            },
            'Pi-Hole': {
                'app': 'PIHOLE',
                'match': ['X-Pi-hole'],
                'title': 'Pi-Hole DNS'
            },
            'Docker Registry': {
                'app': 'DOCKER_REGISTRY',
                'match': ['Docker-Distribution-Api-Version', 'registry/2.0'],
                'title': 'Docker Registry'
            },
            'Symfony': {
                'app': 'SYMFONY',
                'match': ['X-Debug-Token-Link'],
                'title': 'Symfony Debug'
            },
            'MongoExpress': {
                'app': 'MONGO_EXPRESS',
                'match': ['Set-Cookie: mongo-express='],
                'title': 'Mongo Express'
            },
            'OpenVAS': {
                'app': 'OPENVAS',
                'match': ['Greenbone Security Manager'],
                'title': 'OpenVAS Panel'
            },
            'Adminer': {
                'app': 'ADMINER',
                'match': ['adminer.org'],
                'title': 'Adminer PHP'
            },
            'Drupal': {
                'app': 'DRUPAL',
                'match': ['Drupal'],
                'title': 'Drupal CMS'
            },
            'Proxmox': {
                'app': 'PROXMOX',
                'match': ['pve-api-daemon'],
                'title': 'Proxmox Virtual Environment'
            },
        }
        self.intensity = 1

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        response = triage.http_request(ip, port)
        if not response:
            return

        found = False
        for item in self.rule_match_string.values():

            for match in item['match']:
                if triage.string_in_headers(response, match):
                    title = item['title']
                    self.rule_details = f'Exposed {title} at {response.url}'
                    domain = scan_parser.get_domain()
                    vuln_dict = self.get_vuln_dict(ip, port, domain)
                    rds.store_vuln(vuln_dict)
                    found = True
                    break

            if found:
                break
