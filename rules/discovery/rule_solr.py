from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Determine whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/solr': {
                'app': 'APACHE_SOLR',
                'match': ['Solr Admin', 'app_config.solr_path'],
                'title': 'Apache Solr'
            },
        }

        super().__init__(rid='DSC_2200', intensity=1, severity=1,
                         description='This rule checks for the exposure of Apache Solr Panels',
                         confirm='Identified an Apache Solr Panel',
                         details='Apache Solr Panel exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
