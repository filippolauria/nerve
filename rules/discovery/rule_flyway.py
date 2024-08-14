from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        rule_match_string = {
            '/admin': {
                'app': 'FLYWAY',
                'match': ['configprops', 'auditevents'],
                'title': 'Flyway'
            }
        }

        super().__init__(rid='DSC_3GGB', intensity=1, severity=1,
                         description='This rule checks for the exposure of Flyway',
                         confirm='Identified a Flyway App',
                         details='Flyway exposed at the specified URI',
                         mitigation='Identify whether the application in question is supposed to be exposed to the network.',
                         rule_match_string=rule_match_string)
