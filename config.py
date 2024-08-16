from os import environ as env
from os.path import join

APP_NAME = 'NERVIUM'
APP_EXTENDED_NAME = 'Network Exploration, Reconnaissance, Vulnerability, Integrated Unit for continuous Monitoring'

# Logger Configuration
LOG_LEVEL = 'INFO'

# Webserver Configuration
WEB_HOST = '0.0.0.0'  # Listen on all available interfaces
WEB_PORT = 8080  # Port on which the web server will run
WEB_DEBUG = False  # Disable debug mode for production
WEB_USER = env.get('username', '')  # Get username from environment variable
WEB_PASSW = env.get('password', '')  # Get password from environment variable

WEB_LOG_DIR = 'logs'
WEB_LOG_FILE = 'nervium.log'  # Log file for the web server
WEB_LOG_PATH = join(WEB_LOG_DIR, WEB_LOG_FILE)

# Web Security Configuration
WEB_SECURITY = True  # Enable security headers for all responses

# Security headers to be included in responses
WEB_SEC_HEADERS = {
    'CSP': "default-src 'self' 'unsafe-inline'; object-src 'none'; img-src 'self' data:",  # Content Security Policy
    'CTO': 'nosniff',  # X-Content-Type-Options
    'XSS': '1; mode=block',  # X-XSS-Protection
    'XFO': 'DENY',  # X-Frame-Options
    'RP': 'no-referrer',  # Referrer-Policy
    'Server': APP_NAME,  # Server header
}

# Maximum allowed login attempts before banning the remote origin
MAX_LOGIN_ATTEMPTS = 5

# Redis Configuration
RDS_HOST = '127.0.0.1'  # Redis host (localhost for single-node deployment)
RDS_PORT = 6379  # Redis port
RDS_PASSW = None  # Redis password (None if no password is set)

# Scan Configuration
USER_AGENT = APP_NAME  # User agent string for scans

# Default scan configuration for "Quick Start" scan
DEFAULT_SCAN = {
    'targets': {
        'networks': [],  # List of networks to scan
        'excluded_networks': [],  # List of networks to exclude from scan
        'domains': []  # List of domains to scan
    },
    'config': {
        'name': 'Default',
        'description': 'My Default Scan',
        'engineer': 'John Doe',
        'allow_aggressive': 3,  # Level of aggressiveness allowed (0-5)
        'allow_dos': False,  # Whether to allow Denial of Service tests
        'allow_bf': False,  # Whether to allow brute force attacks
        'allow_internet': True,  # Whether to allow internet access during scan
        'dictionary': {
            'usernames': [],  # List of usernames for brute force attacks
            'passwords': []  # List of passwords for brute force attacks
        },
        'scan_opts': {
            'interface': None,  # Network interface to use for scanning
            'max_ports': 100,  # Maximum number of ports to scan
            'custom_ports': [],  # List of specific ports to scan
            'parallel_scan': 50,  # Number of parallel scans
            'parallel_attack': 30,  # Number of parallel attacks
        },
        'post_event': {
            'webhook': None  # Webhook URL for post-scan notifications
        },
        'frequency': 'once'  # Frequency of the scan (e.g., 'once', 'daily', 'weekly')
    }
}
