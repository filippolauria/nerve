from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Determine whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/zabbix/index.php': {
                'app': 'ZABBIX',
                'match': ['Zabbix SIA'],
                'title': 'Zabbix Server'
            },
            '/index.php': {
                'app': 'ZABBIX',
                'match': ['Zabbix SIA'],
                'title': 'Zabbix Server'
            },
        }

        super().__init__(rid='DSC_3GGB', intensity=1, severity=1,
                         description='This rule checks for the exposure of Zabbix Monitoring Panel',
                         confirm='Identified a Zabbix Instance',
                         details='Zabbix Instance exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
