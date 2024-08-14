from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Identify whether the application in question is supposed to be exposed to the network.'
        )

        rule_match_string = {
            '/jolokia/version': {
                'app': 'JOLOKIA1',
                'match': ['dispatcherClasses'],
                'title': 'Jolokia'
            },
            '/jolokia/list': {
                'app': 'JOLOKIA2',
                'match': ['jdk.management.jfr', 'FlightRecorder'],
                'title': 'Jolokia'
            },
        }

        super().__init__(rid='DSC_3TE9', intensity=2, severity=1,
                         description='This rule checks for the exposure of Jolokia Panels',
                         confirm='Identified a Jolokia Panel',
                         details='Jolokia Panel exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
