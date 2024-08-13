from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        details = (
            "The Remote Server's PHP is leaking out environment information, "
            "which may under certain situations reveal sensitive data such as "
            "environment variables, modules installed, etc."
        )

        mitigation = (
            "Disable PHP info by either adding\n"
            "`disable_functions = phpinfo`\n"
            "in php.ini file\n"
            "OR\n"
            "`php_value disable_functions phpinfo`\n"
            "in .htaccess file."
        )

        php_info_paths = [
            '/phpinfo.php', '/php/info.php', '/info.php', '/php.php',
            '/infophp.php', '/php_info.php', '/test.php', '/phpversion.php',
            '/pinfo.php', '/i.php', '/info/phpinfo.php', '/test/info.php',
            '/phpinfo/info.php', '/testphp.php'
        ]

        rule_match_string = {
            path: {
                'app': 'PHP_INFO',
                'match': ['PHP License', 'phpinfo()'],
                'title': 'Default PHP environment page'
            }
            for path in php_info_paths
        }

        super().__init__(rid='CFG_BS3R', intensity=3, severity=2,
                         description='This rule checks for misconfigurations in PHP',
                         confirm='PHP Information Leakage', details=details, mitigation=mitigation,
                         rule_match_string=rule_match_string)
