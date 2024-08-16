from random import choices
from string import ascii_letters, digits

from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def generate_str(self):
        return '/' + ''.join(choices(ascii_letters + digits, k=8))

    def __init__(self):
        mitigation = (
            'Server is configured with one or more frameworks which are incorrectly configured. '
            'Disable any debug modes in the application and ensure proper error handling exists. '
        )

        rule_match_string = {
            self.generate_str(): {
                'app': 'DJANGO',
                'match': [
                    'Using the URLconf defined in',
                    'Django tried these URL patterns',
                    "You're seeing this error because you have <code>DEBUG"
                ],
                'title': 'Django Error'
            },
            self.generate_str(): {
                'app': 'MYSQL',
                'match': [
                    'MySQL Error',
                    'You have an error in your SQL syntax',
                    'mysql_fetch_array'
                ],
                'title': 'MySQL Error'
            },
            self.generate_str(): {
                'app': 'APACHE_TOMCAT',
                'match': [
                    'The full stack trace of the root cause is available',
                    'An exception occurred processing'
                ],
                'title': 'Apache Tomcat Error'
            },
            self.generate_str(): {
                'app': 'APACHE_STRUTS',
                'match': [
                    'Struts has detected an unhandled exception',
                    'Stacktraces',
                    'struts.devMode=false'
                ],
                'title': 'Apache Struts Error'
            },
            self.generate_str(): {
                'app': 'GENERIC',
                'match': ['The debugger caught an exception'],
                'title': 'Generic Error'
            },
            '/public%c0': {
                'app': 'OUCH_JS',
                'match': [
                    'copy exception into clipboard',
                    'Ouch container',
                    'Server/Request Data'
                ],
                'title': 'Ouch JS Error'
            },
            '/public..': {
                'app': 'OUCH_JS',
                'match': [
                    'copy exception into clipboard',
                    'Ouch container',
                    'Server/Request Data'
                ],
                'title': 'Ouch JS Error'
            },
            '/php_errors.log': {
                'app': 'PHP_ERROR_LOG',
                'match': [
                    'require_once',
                    'Fatal error',
                    'Stack trace'
                ],
                'title': 'PHP Error Log'
            }
        }

        super().__init__(rid='VLN_AB1D', intensity=2, severity=2,
                         description='This rule checks for information revealing errors',
                         confirm='application is leaking information', details='Detected information leakage',
                         mitigation=mitigation, rule_match_string=rule_match_string)
