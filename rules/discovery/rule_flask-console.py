from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        rule_match_string = {
            '/console': {
                'app': 'WERKZEUG',
                'match': ['<h1>Interactive Console</h1>'],
                'title': 'Werkzeug Console'
            }
        }

        super().__init__(rid='DSC_38A9', intensity=1, severity=1,
                         description='This rule checks for the exposure of Flask Consoles',
                         confirm='Identified a Flask Console',
                         details='Flask Console exposed at the specified URI',
                         mitigation='Identify whether the application in question is supposed to be exposed to the network.',
                         rule_match_string=rule_match_string)
