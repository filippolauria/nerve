from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Identify whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/debug/pprof/': {
                'app': 'PPROF',
                'match': ['Types of profiles available'],
                'title': 'PProf'
            },
        }

        super().__init__(rid='DSC_EEF1', intensity=1, severity=1,
                         description='This rule checks for the exposure of PProf',
                         confirm='Identified PProf',
                         details='PProf exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
