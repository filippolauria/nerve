import requests
import shlex
import socket
import urllib3

from bs4 import BeautifulSoup
from config import USER_AGENT
from core.logging import logger
from functools import lru_cache
from http.client import RemoteDisconnected
from subprocess import Popen, PIPE
from urllib3.exceptions import ProtocolError


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

exceptions_map = {
    requests.exceptions.ConnectTimeout: 'Timeout',
    urllib3.exceptions.MaxRetryError: 'MaxRetryError',
    requests.exceptions.SSLError: 'SSL Error',
    requests.exceptions.ConnectionError: 'Connection Error',
    requests.exceptions.Timeout: 'Timeout',
    requests.exceptions.ReadTimeout: 'Read Timeout',
    ProtocolError: 'Protocol Error',
    RemoteDisconnected: 'Remote Disconnected'
}


class Triage:
    def __init__(self):
        self.global_timeout = 10
        self.headers = {
            'User-Agent': USER_AGENT
        }

        # this dictionary maps HTTP verbs to the correct requests method
        self.http_verb__requests_method__map = {
            'GET': requests.get,
            'POST': requests.post,
            'HEAD': requests.head,
            'OPTIONS': requests.options,
            'PUT': requests.put,
            'DELETE': requests.delete
        }

        self.severity_labels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    def http_request(self, ip, port, method="GET", params=None, data=None, json=None,
                     headers=None, follow_redirects=True, timeout=None, uri='/', normalize_headers=False):
        method = method.strip().upper()

        if method not in self.http_verb__requests_method__map.keys():
            logger.error(f"HTTP Method '{method}' is not supported.")
            return

        resp = None

        scheme = 'https' if bool('443' in str(port)) else 'http'
        url = f'{scheme}://{ip}:{port}{uri}'

        if headers:
            self.headers = {**headers, **self.headers}

        if not timeout:
            timeout = self.global_timeout

        try:
            # we use the "HTTP verbs => requests method" map to get the correct requests method
            # that can be called here, according to the value of method
            func = self.http_verb__requests_method__map[method]

            # this set of parameters is used by all requests methods that we can call here
            func_params = {
                'verify': False,
                'timeout': timeout,
                'params': params,
                'allow_redirects': follow_redirects,
                'headers': self.headers
            }

            # this set of parameters is additional in case
            # we use POST, PUT or DELETE
            if method in ['POST', 'PUT', 'DELETE']:
                func_params.update({
                    'data': data,
                    'json': json
                })

            # we can call the right requests method with the right parameters
            resp = func(url, **func_params)

            if normalize_headers:
                resp.normalized_headers = {k.lower(): v for k, v in resp.headers.items()}

        except tuple(exceptions_map.keys()) as e:
            error_type = exceptions_map.get(type(e), 'Unknown Error')
            error_message = str(e)
            logger.debug(f'http_request {ip} {port} ({error_type}: {error_message})')
        except Exception as e:
            logger.debug(f'http_request {ip} {port} (Unknown Error: {e})')

        return resp

    def string_in_headers(self, response, string):
        s = string.upper()
        return response if any(s in k.upper() or s in v.upper() for k, v in response.headers.items()) else False

    def get_tcp_socket_banner(self, ip, port, timeout=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_banner = None

        if not timeout:
            timeout = self.global_timeout

        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                socket_banner = str(sock.recv(1024))
        except Exception:
            pass

        finally:
            sock.close()

        return socket_banner

    def is_socket_open(self, ip, port, timeout=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        is_open = False

        if not timeout:
            timeout = self.global_timeout

        sock.settimeout(timeout)

        try:
            is_open = bool(sock.connect_ex((ip, port)) == 0)
        except Exception:
            pass

        finally:
            sock.close()

        return is_open

    def run_cmd(self, command):
        p = Popen(shlex.split(command), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        return stdout if p.returncode == 0 else stderr

    @lru_cache(maxsize=128)
    def has_cves(self, cpe):
        if not any(char.isdigit() for char in cpe):
            return False

        uri = f'/vuln/search/results?form_type=Advanced&cves=on&cpe_version={cpe}'
        req = self.http_request('nvd.nist.gov', 443, method="GET", uri=uri)
        if not req:
            return False

        soup = BeautifulSoup(req.text, 'html.parser')
        severity_links = soup.find_all('a', attrs={'data-testid': True, 'href': True})

        for link in severity_links:
            content = link.contents[0] if link.contents else ''
            if any(label in content for label in self.severity_labels):
                try:
                    score = float(content.split()[0])
                    if score >= 8.9:
                        return True
                except (ValueError, IndexError):
                    continue

        return False
