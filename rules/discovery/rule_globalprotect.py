from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        rule_match_string = {
            '/global-protect/login.esp': {
                'app': 'PAN_GP',
                'match': ['GlobalProtect Portal'],
                'title': 'PAN GlobalProtect'
            },
            '/php/login.php': {
                'app': 'PANOS_PANEL',
                'match': [
                    'BEGIN PAN_FORM_CONTENT', 'js/lib/pan-json.js', 'js/lib/pan-module-injection.js',
                    'js/lib/pan-environment.js', 'js/lib/pan-extjs3.js', 'js/pan/extoverride.js',
                    'js/lib/pan-xml.js', 'js/lib/panos-panos-login.js',
                ],
                'title': 'Palo Alto Panel (PanOS)'
            }
        }

        super().__init__(rid='DSC_100F', intensity=2, severity=1,
                         description='This rule checks for the exposure of Palo Alto Global Protect Panels',
                         confirm='Identified a Global Protect Panel',
                         details='Global Protect Panel or Palo Alto Panel exposed',
                         mitigation='Identify whether the application in question is supposed to be exposed to the network.',
                         rule_match_string=rule_match_string)
