from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Identify whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/prometheus/config': {
                'app': 'PROMETHEUS',
                'match': ['/prometheus/targets'],
                'title': 'Prometheus Monitoring'
            },
            '/graph': {
                'app': 'PROMETHEUS',
                'match': ['Prometheus Time Series Collection and Processing Server'],
                'title': 'Prometheus Server'
            },
        }

        super().__init__(rid='DSC_FOR3', intensity=1, severity=1,
                         description='This rule checks for the exposure of Prometheus Panels',
                         confirm='Identified a Prometheus Panel',
                         details='Prometheus Panel exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
