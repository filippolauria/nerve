import nmap

from core.utils import Utils
from core.triage import Triage
from core.logging import logger


class Fingerprint():
    def __init__(self):
        self.t = Triage()


class Scanner():
    def __init__(self):
        self.nmap = nmap.PortScanner()
        unpriv_scan = "-sV -sT -n --max-retries 10 --host-timeout 60m"

        self.nmap_args = {
            'unpriv_scan': unpriv_scan,
            'priv_scan': f"{unpriv_scan} -O"
        }
        self.utils = Utils()

    def scan(self, hosts, max_ports, custom_ports, interface=None):
        extra_args = ''
        scan_cmdline = 'unpriv_scan'
        ports = ''

        if custom_ports:
            port_list = ','.join([str(p) for p in set(custom_ports)])

            ports = f"-p {port_list}"
        else:
            if not max_ports:
                max_ports = 100

            ports = f"--top-ports {max_ports}"

        if interface:
            extra_args += f"-e {interface}"

        if self.utils.is_user_root():
            scan_cmdline = 'priv_scan'

        data = {}
        hosts = ' '.join(hosts.keys())
        result = {}
        try:
            arguments = " ".join([self.nmap_args[scan_cmdline], ports, extra_args])
            result = self.nmap.scan(hosts, arguments=arguments)
        except nmap.nmap.PortScannerError as e:
            logger.error(f"Error with scan. {e}")

        if 'scan' not in result:
            return data

        for host, res in result['scan'].items():
            data[host] = {
                'status': res['status']['state'],
                'status_reason': res['status']['reason'],
                'domain': None,
                'os': None
            }

            for hostname in res['hostnames']:
                if hostname['type'] == 'user':
                    data[host]['domain'] = hostname['name']
                    break

            if 'osmatch' in res and res['osmatch']:
                for match in res['osmatch']:
                    if int(match['accuracy']) >= 90:
                        data[host]['os'] = match['name']
                        break

            if 'tcp' in res:
                data[host]['port_data'] = {}
                data[host]['ports'] = set()
                for port, values in res['tcp'].items():
                    if port and values['state'] == 'open':
                        data[host]['ports'].add(port)
                        data[host]['port_data'][port] = {
                            'cpe': values['cpe'],
                            'module': values['name'],
                            'state': values['state'],
                            'version': values['version'],
                            'product': values['product']
                        }

        return data
