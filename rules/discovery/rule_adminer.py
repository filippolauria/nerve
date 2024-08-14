from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Identify whether the application in question is supposed to be exposed to the network.'
        )

        rule_match_string = {
            '/adminer.php': {
                'app': 'Adminer PHP',
                'match': ['adminer.org'],
                'title': 'Adminer PHP'
            },
        }

        super().__init__(rid='DSC_GEAZ', intensity=1, severity=1,
                         description='This rule checks for the exposure of Adminer Panel.',
                         confirm='Identified an Adminer Panel', details='Adminere Panel exposed',
                         mitigation=mitigation, rule_match_string=rule_match_string)
