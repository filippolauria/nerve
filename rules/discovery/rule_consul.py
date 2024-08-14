from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        rule_match_string = {
            '/ui': {
                'app': 'HASHICORP_CONSUL',
                'match': ['Consul by HashiCorp', 'consul-ui/config/environment'],
                'title': 'HashiCorp Consul'
            }
        }

        super().__init__(rid='DSC_2435', intensity=1, severity=1,
                         description='This rule checks for the exposure of Hashicorp Consul Panels',
                         confirm='Identified a Hashicorp Consul Panel',
                         details='Exposed HashiCorp Consul Panel at the specified URI',
                         mitigation='Identify whether the application in question is supposed to be exposed to the network.',
                         rule_match_string=rule_match_string)
