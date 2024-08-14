from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Identify whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/phpmoadmin': {
                'app': 'PHP_MOADMIN',
                'match': ['mongo_rows'],
                'title': 'MongoDB Admin'
            },
            '/moadmin': {
                'app': 'PHP_MOADMIN',
                'match': ['mongo_rows'],
                'title': 'MongoDB Admin'
            },
        }

        super().__init__(rid='DSC_3TGT', intensity=1, severity=1,
                         description='This rule checks for the exposure of MongoAdmin Panel',
                         confirm='Identified a MongoAdmin Web Panel',
                         details='MongoAdmin Web Panel exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
