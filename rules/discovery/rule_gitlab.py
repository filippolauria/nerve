from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Determine whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/users/sign_in': {
                'app': 'GITLAB1',
                'match': ['user[password]'],
                'title': 'GitLab'
            },
            '/users/sign_up': {
                'app': 'GITLAB2',
                'match': ['user[password]'],
                'title': 'GitLab'
            },
            '/explore': {
                'app': 'GITLAB3',
                'match': ['Explore projects'],
                'title': 'GitLab'
            },
        }

        super().__init__(rid='DSC_OR39', intensity=2, severity=1,
                         description='This rule checks for the exposure of GitLab Panels',
                         confirm='Identified a GitLab Panel',
                         details='GitLab Panels exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
