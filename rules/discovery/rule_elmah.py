from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        rule_match_string = {
            '/elmah.axd': {
                'app': 'ELMAH',
                'match': ['Powered by ELMAH', 'Error Log or'],
                'title': 'Elmah'
            }
        }

        super().__init__(rid='DSC_3E39', intensity=1, severity=1,
                         description='This rule checks for the exposure of Elmah Panels',
                         confirm='Identified an Elmah Panel',
                         details='Exposed Elmah at the specified URI',
                         mitigation='Identify whether the application in question is supposed to be exposed to the network.',
                         rule_match_string=rule_match_string)
