from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = 'Disable the ability to directly browse to file system paths'

        rule_match_string = {
            '/.ssh/authorized_keys': {
                'app': 'SSH_AUTH_KEYS',
                'match': ['ssh-rsa'],
                'title': 'SSH Authorized Keystore'
            },
            '/etc/hosts': {
                'app': 'LOCAL_HOSTS_FILE',
                'match': ['localhost is used to configure'],
                'title': 'Local Host Resolver'
            },
            '/etc/passwd': {
                'app': 'UNIX_PASSWD_FILE',
                'match': ['root:x:0:0'],
                'title': 'UNIX Local Users File'
            },
            '/etc/shadow': {
                'app': 'UNIX_SHADOW_FILE',
                'match': ['bin:x:', 'nobody:x:'],
                'title': 'UNIX Hashes File Leak'
            },
            '/.ssh/id_rsa': {
                'app': 'SSH_PRIVATE_KEY',
                'match': ['-----BEGIN RSA PRIVATE KEY-----'],
                'title': 'Private SSH Key Leak'
            },
            '/.ssh/id_rsa.pub': {
                'app': 'SSH_PUBLIC_KEY',
                'match': ['ssh-rsa'],
                'title': 'SSH Public Key'
            },
            '/etc/mysql/my.cnf': {
                'app': 'MYSQL_CONFIG',
                'match': ['[mysqld]'],
                'title': 'MySQL Configuration File'
            },
        }

        super().__init__(rid='VLN_EZSD', intensity=2, severity=4,
                         description='This rule checks for exposed UNIX Filesystems',
                         confirm='UNIX File Disclosure',
                         details='UNIX File Disclosure',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
