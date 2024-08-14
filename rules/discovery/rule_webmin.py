from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Determine whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/webmin': {
                'app': 'WEBMIN',
                'match': ['login to the Webmin server', 'Login to Webmin'],
                'title': 'Webmin Management Portal'
            },
            '/': {
                'app': 'WEBMIN',
                'match': ['login to the Webmin server', 'Login to Webmin'],
                'title': 'Webmin Management Portal'
            },
        }

        super().__init__(rid='DSC_OWA9', intensity=1, severity=1,
                         description='This rule checks for the exposure of Webmin Panels',
                         confirm='Identified a Webmin Panel',
                         details='Webmin Management Portal exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
