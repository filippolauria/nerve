from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        rule_match_string = {
            '/__clockwork/app': {
                'app': 'CLOCKWORK',
                'match': ['<title>Clockwork</title>'],
                'title': 'Clockwork'
            }
        }

        super().__init__(rid='DSC_38A9', intensity=1, severity=1,
                         description='This rule checks for the exposure of Clockwork Panels',
                         confirm='Identified a Clockwork Panel',
                         details='Exposed Clockwork Panel at the specified URI',
                         mitigation='Identify whether the application in question is supposed to be exposed to the network.',
                         rule_match_string=rule_match_string)
