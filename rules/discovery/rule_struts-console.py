from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Determine whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/struts/webconsole.html': {
                'app': 'OGNL_CONSOLE',
                'match': ['OGNL console'],
                'title': 'OGNL Console'
            },
        }

        super().__init__(rid='DSC_BFL9', intensity=1, severity=1,
                         description='This rule checks for the exposure of Struts Consoles',
                         confirm='Identified a Struts Console',
                         details='Struts Console exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
