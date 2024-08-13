from core.parser import ScanParser
from core.redis import rds
from core.rules import BaseRule
from core.triage import Triage


class Rule(BaseRule):
    def __init__(self):
        super().__init__()
        self.rule = 'CFG_E9AF'
        self.rule_severity = 0
        self.rule_description = 'This rule checks if a Default Page is Served by a Web Server'
        self.rule_confirm = 'Unmaintained Webserver'
        self.rule_details = ''
        self.rule_mitigation = (
            'Server is configured with the default web server page. '
            'This may indicate a forgotten/unmaintained server, and may not necessarily pose a security concern.'
        )

        self.rule_match_string = {
            'Apache': {
                'app': 'APACHE',
                'match': ['Are you the administrator?'],
                'title': 'Apache Default Page'
            },
            'Apache2': {
                'app': 'APACHE2',
                'match': ['Apache 2 Test Page', 'It works!'],
                'title': 'Apache2 Default Page'
            },
            'Apache2 Debian': {
                'app': 'APACHE2_DEBIAN',
                'match': ['Apache2 Debian Default Page'],
                'title': 'Apache2 Debian Default Page'
            },
            'Apache2 Ubuntu': {
                'app': 'APACHE2_UBUNTU',
                'match': ['Apache2 Ubuntu Default Page'],
                'title': 'Apache2 Ubuntu Default Page'
            },
            'Nginx': {
                'app': 'NGINX',
                'match': ['Welcome to nginx!'],
                'title': 'Nginx Default Page'
            },
            'NodeJS Express': {
                'app': 'NODEJS_EXPRESS',
                'match': ['Welcome to Express'],
                'title': 'NodeJS Express Default Page'
            },
            'Lighttpd': {
                'app': 'LIGHTTPD',
                'match': ['Lighttpd server package', 'lighty-enable-mod'],
                'title': 'Lighttpd Default Page'
            },
            'IIS7': {
                'app': 'MS_IIS',
                'match': ['img src="welcome.png" alt="IIS7"', 'img src="iisstart.png" alt="IIS"'],
                'title': 'MS IIS Default Page'
            },
            'Django': {
                'app': 'DJANGO',
                'match': ['The install worked successfully!'],
                'title': 'Django Default Page'
            },
            'ASP.NET': {
                'app': 'ASPNET',
                'match': ['ASP.NET is a free web framework'],
                'title': 'ASP.NET Default Page'
            },
            'LightSpeed': {
                'app': 'LIGHTSPEED',
                'match': ['installed the OpenLiteSpeed Web Server!'],
                'title': 'LightSpeed Default Page'
            },
            'Fedora': {
                'app': 'FEDORA',
                'match': ['Fedora Test Page'],
                'title': 'Fedora Default Page'
            },
            'RHEL': {
                'app': 'RHEL',
                'match': ['Red Hat Enterprise Linux Test Page'],
                'title': 'Red Hat Default Page'
            },
            'OpenResty': {
                'app': 'OPENRESTY',
                'match': ['flying OpenResty'],
                'title': 'OpenResty Default Page'
            },
            'Caddy': {
                'app': 'CADDY',
                'match': ['Caddy is serving this page'],
                'title': 'Caddy Default Page'
            },
            'Cherokee': {
                'app': 'CHEROKEE',
                'match': ['Cherokee Web Server'],
                'title': 'Cherokee Default Page'
            },
            'Tomcat': {
                'app': 'TOMCAT',
                'match': ['Apache Tomcat', 'Tomcat Manager'],
                'title': 'Tomcat Default Page'
            },
            'Jenkins': {
                'app': 'JENKINS',
                'match': ['Jenkins is fully up and running'],
                'title': 'Jenkins Default Page'
            },
            'GlassFish': {
                'app': 'GLASSFISH',
                'match': ['GlassFish Server Open Source Edition'],
                'title': 'GlassFish Default Page'
            },
            'Meteor': {
                'app': 'METEOR',
                'match': ['Meteor App'],
                'title': 'Meteor Default Page'
            },
            'Plesk': {
                'app': 'PLESK',
                'match': ['Plesk default page'],
                'title': 'Plesk Default Page'
            },
            'WebLogic': {
                'app': 'WEBLOGIC',
                'match': ['Oracle WebLogic Server'],
                'title': 'WebLogic Default Page'
            },
            'WebSphere': {
                'app': 'WEBSPHERE',
                'match': ['IBM WebSphere Application Server'],
                'title': 'WebSphere Default Page'
            },
            'Blynk': {
                'app': 'BLYNK',
                'match': ['Blynk Server'],
                'title': 'Blynk Default Page'
            },
            'Phusion Passenger': {
                'app': 'PHUSION_PASSENGER',
                'match': ['Phusion Passenger'],
                'title': 'Phusion Passenger Default Page'
            },
            'Hiawatha': {
                'app': 'HIAWATHA',
                'match': ['Hiawatha Webserver'],
                'title': 'Hiawatha Default Page'
            },
            'Nette': {
                'app': 'NETTE',
                'match': ['Nette Framework'],
                'title': 'Nette Default Page'
            },
            'Symfony': {
                'app': 'SYMPHONY',
                'match': ['Welcome to Symfony'],
                'title': 'Symfony Default Page'
            },
            'Gogs': {
                'app': 'GOGS',
                'match': ['Gogs - Go Git Service'],
                'title': 'Gogs Default Page'
            }
        }

        self.intensity = 1

    def check_rule(self, ip, port, values, conf):
        scan_parser = ScanParser(port, values)

        if not scan_parser.is_module('http'):
            return

        triage = Triage()
        response = triage.http_request(ip, port, uri='/')

        if not response:
            return

        for app, val in self.rule_match_string.items():
            match_list = val['match']
            title = val["title"]

            if self.check_match(response, match_list):
                self.rule_details = f'Identified a {title} on {response.url}'
                domain = scan_parser.get_domain()
                vuln_dict = self.get_vuln_dict(ip, port, domain)
                rds.store_vuln(vuln_dict)
