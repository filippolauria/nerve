from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Identify whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/examples/jsp/snp/snoop.jsp': {
                'app': 'SNOOP_JSP',
                'match': ['Authorization scheme', 'Servlet path:', 'Remote host'],
                'title': 'Snoop JSP'
            },
        }

        super().__init__(rid='DSC_0119', intensity=1, severity=1,
                         description='This rule checks for the exposure of Snoop JSP',
                         confirm='Identified a Snoop JSP',
                         details='Snoop JSP exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
