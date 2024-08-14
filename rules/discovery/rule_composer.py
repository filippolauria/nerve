from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        rule_match_string = {
            '/composer.json': {
                'app': 'COMPOSER_JSON',
                'match': ['"require": {'],
                'title': 'Composer'
            }
        }

        super().__init__(rid='DSC_38A9', intensity=1, severity=2,
                         description='This rule checks for the exposure of Composer JSON',
                         confirm='Identified a Composer JSON',
                         details='Exposed Composer JSON at the specified URI',
                         mitigation='Identify whether the file in question is supposed to be exposed to the network.',
                         rule_match_string=rule_match_string)
