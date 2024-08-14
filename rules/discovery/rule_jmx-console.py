from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        rule_match_string = {
            '/jmx-console': {
                'app': 'JMX_CONSOLE',
                'match': ['JBoss JMX Management Console'],
                'title': 'JMX Console'
            },
        }

        super().__init__(rid='DSC_11A9', intensity=1, severity=1,
                         description='This rule checks for the exposure of JMX Consoles',
                         confirm='Identified a JMX Console',
                         details='JMX Console exposed',
                         mitigation='Identify whether the application in question is supposed to be exposed to the network.',
                         rule_match_string=rule_match_string)
