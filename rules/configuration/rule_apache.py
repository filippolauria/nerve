from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Apache Web Server is misconfigured and exposes one or more files related to configuration, statistics or example servlets.\n'
            'Refer to an Apache Hardening Guideline for more information: https://geekflare.com/apache-web-server-hardening-security/'
        )

        rule_match_string = {
            '/server-status': {
                'app': 'APACHE_SERVER_STATUS',
                'match': ['Total accesses', 'Parent Server Generation', 'Server uptime'],
                'title': 'Apache Server Status Page'
            },
            '/.htaccess': {
                'app': 'APACHE_HTACCESS_FILE',
                'match': ['RewriteEngine', 'IfModule'],
                'title': 'htaccess File'
            },
            '/server-info': {
                'app': 'APACHE_SERVER_INFO',
                'match': ['Apache Server Info', 'Request Hooks'],
                'title': 'Apache Server Info'
            },
            '/examples': {
                'app': 'APACHE_TOMCAT_EXAMPLES',
                'match': ['Serverlets examples', 'JSP Examples', 'WebSocket Examples'],
                'title': 'Apache Tomcat Examples'
            },
        }

        super().__init__(rid='CFG_91Z0', intensity=3, severity=1,
                         description='This rule checks for Apache Web Server Misconfigurations',
                         confirm='Misconfigured Apache Server', details='Apache misconfiguration',
                         mitigation=mitigation, rule_match_string=rule_match_string)
