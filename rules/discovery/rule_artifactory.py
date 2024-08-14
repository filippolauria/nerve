from core.rules import BasicWebRule


class Rule(BasicWebRule):
    def __init__(self):
        mitigation = (
            'Determine whether the application in question should be exposed to the network.'
        )

        rule_match_string = {
            '/artifactory/webapp': {
                'app': 'JFROG_ARTIFACTORY',
                'match': ['artifactory.ui', 'artifactory_views'],
                'title': 'Artifactory'
            },
            '/artifactory/libs-release': {
                'app': 'JFROG_LIB_RELEASE',
                'match': ['Index of libs-release/'],
                'title': 'Artifactory Directory Exposure'
            },
        }

        super().__init__(rid='DSC_SSB9', intensity=1, severity=2,
                         description='This rule checks for the exposure of Artifactory Panels.',
                         confirm='Identified an Artifactory Panel',
                         details='Artifactory Panels exposed',
                         mitigation=mitigation,
                         rule_match_string=rule_match_string)
