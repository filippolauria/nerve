import socket
from socket import gethostname
from core.utils import Network, Utils


class SchemaParser:
    def __init__(self, data, req):
        self.data = data
        self.utils = Utils()
        self.netutils = Network()
        self.metadata = {
            'unique_id': self.utils.generate_uuid(),
            'timestamp': self.utils.get_datetime(),
            'node': gethostname(),
            'issuer': {
                'user_agent': req.headers.get('User-Agent'),
                'source_ip': req.remote_addr
            }
        }
        self.data['metadata'] = self.metadata

    def verify(self):
        verified = True
        error = None

        try:
            # Targets
            networks = self.data['targets']['networks']
            excluded_networks = self.data['targets']['excluded_networks']
            domains = self.data['targets']['domains']

            # Scan Definition
            name = self.data['config']['name']
            description = self.data['config']['description']
            engineer = self.data['config']['engineer']
            webhook = self.data['config']['post_event']['webhook']
            intrusive_level = self.data['config']['allow_aggressive']
            allow_dos = self.data['config']['allow_dos']
            allow_bf = self.data['config']['allow_bf']
            allow_inet = self.data['config']['allow_internet']
            dictionary_usernames = self.data['config']['dictionary']['usernames']
            dictionary_passwords = self.data['config']['dictionary']['passwords']
            max_ports = self.data['config']['scan_opts']['max_ports']
            custom_ports = self.data['config']['scan_opts']['custom_ports']
            net_interface = self.data['config']['scan_opts']['interface']
            parallel_scan = self.data['config']['scan_opts']['parallel_scan']
            parallel_attack = self.data['config']['scan_opts']['parallel_attack']
            frequency = self.data['config']['frequency']

            """
            Check Structure
            """
            if not isinstance(name, str):
                error = 'Option [ASSESSMENT_NAME] must be a String'
                verified = False

            if not isinstance(networks, list):
                error = 'Option [NETWORKS] must be an Array'
                verified = False

            if not isinstance(excluded_networks, list):
                error = 'Option [EXCLUDED_NETWORKS] must be an Array'
                verified = False

            if not isinstance(domains, list):
                error = 'Option [DOMAINS] must be an Array'
                verified = False

            if not isinstance(intrusive_level, int):
                error = 'Option [AGGRESSIVENESS_LEVEL] must be an Integer'
                verified = False

            if not isinstance(allow_dos, bool):
                error = 'Option [ALLOW_DENIAL_OF_SERVICE] must be a Boolean'
                verified = False

            if not isinstance(allow_inet, bool):
                error = 'Option [ALLOW_INTERNET_OUTBOUND] must be a Boolean'
                verified = False

            if not isinstance(allow_bf, bool):
                error = 'Option [ALLOW_BRUTE_FORCE] must be a Boolean'
                verified = False

            if not isinstance(dictionary_usernames, list):
                error = 'Option [DICTIONARY_USERNAMES] must be an Array'
                verified = False

            if not isinstance(dictionary_passwords, list):
                error = 'Option [DICTIONARY_PASSWORDS] must be an Array'
                verified = False

            if not isinstance(net_interface, (str, type(None))):
                error = 'Option [NET_INTERFACE] must be null or a String'
                verified = False

            if not isinstance(max_ports, int):
                error = 'Option [MAX_PORTS] must be an Integer'
                verified = False

            if not isinstance(custom_ports, list):
                error = 'Option [CUSTOM_PORTS] must be an Array'
                verified = False

            if not isinstance(parallel_scan, int):
                error = 'Option [PARALLEL_SCAN] must be an Integer'
                verified = False

            if not isinstance(parallel_attack, int):
                error = 'Option [PARALLEL_ATTACK] must be an Integer'
                verified = False

            if not isinstance(webhook, (str, type(None))):
                error = 'Option [WEB_HOOK] must be null or a String'
                verified = False

            if not isinstance(frequency, str):
                error = 'Option [FREQUENCY] must be a String'
                verified = False

            if not verified:
                return (verified, error, self.data)

            """
            Check passed values
            """

            if len(name) > 30 or not self.utils.is_string_safe(name):
                error = 'Option [ASSESSMENT_NAME] must not exceed 30 characters and must not have special characters.'
                verified = False

            if description:
                if len(description) > 50 or not self.utils.is_string_safe(description):
                    error = 'Option [ASSESSMENT_DESCRIPTION] must not exceed 200 characters and must not have special characters.'
                    verified = False

            if engineer:
                if len(engineer) > 20 or not self.utils.is_string_safe(engineer):
                    error = 'Option [ENGINEER] must not exceed 20 characters and must not have special characters.'
                    verified = False

            if webhook:
                if not self.utils.is_string_url(webhook):
                    error = 'Option [WEB_HOOK] must be a valid URL.'
                    verified = False

            if frequency not in ('once', 'continuous'):
                error = 'Option [SCHEDULE] must be "once" or "continuous"'
                verified = False

            if not 0 <= intrusive_level <= 3:
                error = 'Option [AGGRESSIVE_LEVEL] must be between 0-3'
                verified = False

            if max_ports:
                if not self.netutils.is_valid_port(max_ports):
                    error = 'Option [MAX_PORTS] must be a value between 0-65535'
                    verified = False

            if custom_ports:
                for cport in custom_ports:
                    if not self.netutils.is_valid_port(cport):
                        error = 'Option [CUSTOM_PORTS] must be an array of values between 0-65535'
                        verified = False

            if not networks and not domains:
                error = 'Options [DOMAINS] or Options [NETWORKS] must not be empty'
                verified = False

            if networks:
                for network in networks:
                    try:
                        if not self.netutils.is_network(network):
                            error = 'Option [NETWORKS] must be a valid network CIDR'
                            raise ValueError
                        elif self.netutils.is_network_in_denylist(network):
                            error = 'Option [NETWORKS] is not allowed'
                            raise ValueError

                    except ValueError:
                        verified = False

            if excluded_networks:
                for network in excluded_networks:
                    try:
                        if not self.netutils.is_network(network):
                            raise ValueError
                    except ValueError:
                        error = 'Option [EXCLUDED NETWORKS] must be a valid network CIDR'
                        verified = False

            if domains:
                for domain in domains:
                    if not self.netutils.is_dns(domain):
                        error = 'Option [DOMAINS] must contain valid domains (and they must be resolveable!)'
                        verified = False

            if net_interface:
                n = Network()
                if net_interface not in n.get_nics():
                    error = 'Option [NET_INTERFACE] must be valid'
                    verified = False

            else:
                self.data['config']['scan_opts']['interface'] = None

            if not 1 <= parallel_attack <= 100:
                error = 'Option [ATTACK_THREADS] must be between 1-100'
                verified = False

            if not 1 <= parallel_scan <= 100:
                error = 'Option [SCAN_THREADS] must be between 1-100'
                verified = False

        except KeyError as e:
            error = f"One or more options are missing: {e}"
            verified = False

        return (verified, error, self.data)

    def get_cfg(self):
        return self.data


class ScanParser:
    def __init__(self, port, values):
        self.port_data = values['port_data'][port]
        self.ports = values['ports']
        self.domain = values['domain']

    def get_cpe(self):
        return self.port_data['cpe']

    def get_version(self):
        return self.port_data['version']

    def get_module(self):
        return self.port_data['module']

    def is_module(self, module):
        return module in self.get_module().strip().lower()

    def get_product(self):
        return self.port_data['product'] if self.port_data['product'] else 'N/A'

    def is_product(self, product):
        return self.port_data['product'] and product in self.port_data['product'].strip().lower()

    def get_portstate(self):
        return self.port_data['state']

    def get_ports(self):
        return self.ports

    def get_domain(self):
        return self.domain


class ConfParser:
    def __init__(self, cfg):
        self.values = cfg
        self.metadata = cfg['metadata']
        self.targets = cfg['targets']

        self.config = cfg['config']
        self.scan_opts = self.config['scan_opts']

    def get_raw_cfg(self):
        return self.values

    def get_cfg_metadata(self):
        return self.metadata

    def get_cfg_scan_config(self):
        return self.config

    def get_cfg_scan_targets(self):
        return self.targets

    def get_cfg_scan_id(self):
        return self.metadata['unique_id']

    def get_cfg_networks(self):
        return self.targets['networks']

    def get_cfg_exc_networks(self):
        return self.targets['excluded_networks']

    def get_cfg_domains(self):
        return self.targets['domains']

    def get_cfg_aggressive_lvl(self):
        return self.config['allow_aggressive']

    def get_cfg_allow_dos(self):
        return self.config['allow_dos']

    def get_cfg_allow_inet(self):
        return self.config['allow_internet']

    def get_cfg_allow_bf(self):
        return self.config['allow_bf']

    def get_cfg_usernames(self):
        return self.config['dictionary']['usernames']

    def get_cfg_passwords(self):
        return self.config['dictionary']['passwords']

    def get_cfg_webhook(self):
        return self.config['post_event']['webhook']

    def get_cfg_frequency(self):
        return self.config['frequency']

    def get_cfg_max_ports(self):
        return self.scan_opts['max_ports']

    def get_cfg_custom_ports(self):
        return self.scan_opts['custom_ports']

    def get_cfg_netinterface(self):
        return self.scan_opts['interface']

    def get_cfg_attack_threads(self):
        return self.scan_opts['parallel_attack']

    def get_cfg_scan_threads(self):
        return self.scan_opts['parallel_scan']


class Helper:
    def cpe_hyperlink(self, cpe):
        return f'<a href="https://nvd.nist.gov/vuln/search/results?cpe_version={cpe}">CVE List</a>'

    def cve_hyperlink(self, cve):
        return f'<a href="https://nvd.nist.gov/vuln/detail/{cve}">{cve}</a>'

    def port_translate(self, port):
        translation = 'Unknown'
        try:
            translation = socket.getservbyport(port)
        except OSError:
            pass
        return translation
