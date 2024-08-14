from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Identify whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/api/jsonws/invoke': {
                'app': 'LifeRay JSON API',
                'match': ['"_type":"jsonws"'],
                'title': 'LifeRay'
            },
        }

        super().__init__(rid='DSC_GQW9', intensity=1, severity=1,
                         description='This rule checks for the exposure of LifeRay Panels',
                         confirm='Identified a LifeRay Panel',
                         details='LifeRay Panel exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
