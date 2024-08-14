from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Identify whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/login': {
                'app': 'REDASH',
                'match': ['Login to Redash'],
                'title': 'Redash'
            }
        }

        super().__init__(rid='DSC_KKW9', intensity=1, severity=1,
                         description='This rule checks for the exposure of Redash Panels',
                         confirm='Identified a Redash Panel',
                         details='Redash Panel exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
