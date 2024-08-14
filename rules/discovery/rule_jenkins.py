from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Determine whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/jenkins': {
                'app': 'JENKINS',
                'match': ['Dashboard [Jenkins]', 'Deployables [Jenkins]', '/jenkins/static/'],
                'title': 'Jenkins'
            },
        }

        super().__init__(rid='DSC_TGGS', intensity=1, severity=1,
                         description='This rule checks for the exposure of Jenkins',
                         confirm='Identified a Jenkins Instance', details='Jenkins instance exposed',
                         mitigation=mitigation, rule_match_string=rule_match_string)
