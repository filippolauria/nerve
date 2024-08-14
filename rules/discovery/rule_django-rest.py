from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        rule_match_string = {
            '/api/users': {
                'app': 'DJANGO_API_USERS',
                'match': ['is_staff'],
                'title': 'Django REST Users List'
            }
        }

        super().__init__(rid='DSC_BSZ2', intensity=1, severity=2,
                         description='This rule checks for the exposure of Django Users API Endpoints',
                         confirm='Identified a Django API Endpoint',
                         details='Exposed Django REST Users List at the specified URI',
                         mitigation='Identify whether the application in question is supposed to be exposed to the network.',
                         rule_match_string=rule_match_string)
