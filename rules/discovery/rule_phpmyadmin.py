from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Identify whether the application in question should be exposed to the network.'
        )

        common_match = [
            'Welcome to phpMyAdmin',
            'phpmyadmin.css',
            'phpMyAdmin is more friendly with'
        ]
        rule_match_string = {
            '/phpmyadmin/index.php': {
                'app': 'PHP_MYADMIN',
                'match': common_match,
                'title': 'PHPMyAdmin'
            },
            '/pma/index.php': {
                'app': 'PHP_MYADMIN',
                'match': common_match,
                'title': 'PHPMyAdmin'
            },
        }

        super().__init__(rid='DSC_3GG3', intensity=1, severity=1,
                         description='This rule checks for the exposure of PHPMyAdmin Panels',
                         confirm='Identified a PHPMyAdmin Web Panel',
                         details='PHPMyAdmin Web Panel exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
