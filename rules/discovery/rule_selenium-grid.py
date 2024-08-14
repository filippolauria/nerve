from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Identify whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/grid/console': {
                'app': 'SELENIUM_GRID',
                'match': ['DefaultRemoteProxy', 'hubConfig', 'grid/register', 'DefaultGridRegistry'],
                'title': 'Selenium Grid'
            },
        }

        super().__init__(rid='DSC_TOOA', intensity=1, severity=1,
                         description='This rule checks for the exposure of Selenium Grid Panels',
                         confirm='Identified a Selenium Grid Instance',
                         details='Selenium Grid Panel exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
