from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Determine whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/node': {
                'app': 'HADOOP_RM',
                'match': ['Hadoop Version', 'List of Applications', 'Hadoop:*'],
                'title': 'Hadoop Resource Manager'
            },
        }

        super().__init__(rid='DSC_3561', intensity=1, severity=1,
                         description='This rule checks for the exposure of Hadoop Resource Manager Panels.',
                         confirm='Identified a Hadoop RM Panel',
                         details='Hadoop Resource Manager Panel exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
