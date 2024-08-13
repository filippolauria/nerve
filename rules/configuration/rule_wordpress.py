from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Wordpress may have been misconfigured and potentially leaks application data.\n'
            'Remove any unnecessary files from the webserver which could potentially leak '
            'environment details of your Wordpress instance'
        )

        common_wp_config_match = ['wp-settings.php', 'DB_PASSWORD', 'MySQL settings']
        rule_match_string = {
            '/wp-config.old': {
                'app': 'WORDPRESS',
                'match': common_wp_config_match,
                'title': 'Wordpress Backup File'
            },
            '/wp-config.php': {
                'app': 'WORDPRESS',
                'match': common_wp_config_match,
                'title': 'Wordpress Configuration File'
            },
            '/wp-config.php.bak': {
                'app': 'WORDPRESS_PHP_BAK',
                'match': common_wp_config_match,
                'title': 'Wordpress Backup File'
            },
            '/wp-config.php.old': {
                'app': 'WORDPRESS_PHP_OLD',
                'match': common_wp_config_match,
                'title': 'Wordpress Backup File'
            },
            '/wp-config.php.save': {
                'app': 'WORDPRESS_SAVE',
                'match': common_wp_config_match,
                'title': 'Wordpress Backup File'
            },
            '/wp-config.php~': {
                'app': 'WORDPRESS_VI_BACKUP',
                'match': common_wp_config_match,
                'title': 'Wordpress Backup File (vi)'
            },
            '/wp-config.php.swp': {
                'app': 'WORDPRESS_VI_SWAP',
                'match': common_wp_config_match,
                'title': 'Wordpress Backup File (vi swap)'
            },
            '/.wp-config.php.swp': {
                'app': 'WORDPRESS_VI_SWAP',
                'match': common_wp_config_match,
                'title': 'Wordpress Backup File (vi swap)'
            },
            '/wp-content/debug.log': {
                'app': 'WORDPRESS_DEBUG_LOG',
                'match': ['PHP Notice', 'Debugging_in_WordPress', 'PHP Warning', 'PHP Stack trace'],
                'title': 'Wordpress Debug Log'
            },
            '/wp-content/backup-db/': {
                'app': 'WORDPRESS_DB_BACKUP',
                'match': ['wp-config.php', 'DB_PASSWORD'],
                'title': 'Wordpress Database Backup Directory'
            },
            '/wp-json/wp/v2/users': {
                'app': 'WORDPRESS_USERS',
                'match': [
                    '"collection":[{"href":', '"_links":{"self":[{"href":""}]',
                    'avatar_urls', '"meta":[],'
                ],
                'title': 'WordPress Username Disclosure'
            },
            '/wp-json/wp/v2/comments': {
                'app': 'WORDPRESS_COMMENTS',
                'match': ['comment_content', 'comment_author', 'comment_date'],
                'title': 'WordPress Comments Disclosure'
            },
            '/wp-json/wp/v2/posts': {
                'app': 'WORDPRESS_POSTS',
                'match': ['post_title', 'post_content', 'post_author'],
                'title': 'WordPress Posts Disclosure'
            },
            '/wp-content/cache/': {
                'app': 'WORDPRESS_CACHE',
                'match': ['cache', 'cached', 'temp'],
                'title': 'Wordpress Cache Directory'
            },
        }

        super().__init__(rid='CFG_8BA9', intensity=2, severity=3,
                         description='This rule checks for misconfigurations in the blog platform Wordpress.',
                         confirm='Misconfigured Wordpress', details='Wordpress Misconfiguration',
                         mitigation=mitigation, rule_match_string=rule_match_string)
