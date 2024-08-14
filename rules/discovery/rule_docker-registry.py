from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        rule_match_string = {
            '/v2/_catalog': {
                'app': 'DOCKER_REGISTRY_LIST',
                'match': ['"repositories":'],
                'title': 'Docker Registry List'
            }
        }

        super().__init__(rid='DSC_55A9', intensity=1, severity=3,
                         description='This rule checks for the exposure of Docker Registry Endpoints',
                         confirm='Identified a Docker Registry Endpoint',
                         details='Exposed Docker Registry List at the specified URI',
                         mitigation='Identify whether the application in question is supposed to be exposed to the network.',
                         rule_match_string=rule_match_string)
