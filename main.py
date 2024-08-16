import config
import os
import re
import sys

from core.redis import rds
from core.workers import start_workers

from flask import Flask
from flask_restful import Api
from version import VERSION
from werkzeug.security import generate_password_hash

# Import Blueprints
from views.view_index import index
from views.view_docs import documentation
from views.view_dashboard import dashboard
from views.view_reports import reports
from views.view_assessment import assessment
from views.view_topology import topology
from views.view_assets import assets
from views.view_welcome import welcome
from views.view_qs import qs
from views.view_login import login
from views.view_console import console
from views.view_logout import logout
from views.view_download import download
from views.view_stream import stream
from views.view_settings import settings
from views.view_scan import scan
from views.view_vulns import vulns
from views.view_alert import alert
from views.view_startover import startover

# Import REST API Endpoints
from views_api.api_health import Health
from views_api.api_scan import Scan
from views_api.api_update import Update
from views_api.api_exclusions import Exclusion

app = Flask(__name__)

# Initialize Blueprints
app.register_blueprint(index)
app.register_blueprint(login)
app.register_blueprint(logout)
app.register_blueprint(welcome)
app.register_blueprint(download)
app.register_blueprint(assets)
app.register_blueprint(stream)
app.register_blueprint(console)
app.register_blueprint(documentation)
app.register_blueprint(dashboard)
app.register_blueprint(qs)
app.register_blueprint(reports)
app.register_blueprint(assessment)
app.register_blueprint(topology)
app.register_blueprint(vulns)
app.register_blueprint(settings)
app.register_blueprint(scan)
app.register_blueprint(alert)
app.register_blueprint(startover)

app.config.update(
    SESSION_COOKIE_SAMESITE='Strict',
)
app.secret_key = os.urandom(24)

api = Api(app)
api.add_resource(Health, '/health')
api.add_resource(Update, '/api/update', '/api/update/<string:component>')
api.add_resource(Scan, '/api/scan', '/api/scan/<string:action>')
api.add_resource(Exclusion, '/api/exclusion', '/api/exclusion')


# Set Security Headers
@app.after_request
def add_security_headers(response):
    if config.WEB_SECURITY:
        response.headers['Content-Security-Policy'] = config.WEB_SEC_HEADERS['CSP']
        response.headers['X-Content-Type-Options'] = config.WEB_SEC_HEADERS['CTO']
        response.headers['X-XSS-Protection'] = config.WEB_SEC_HEADERS['XSS']
        response.headers['X-Frame-Options'] = config.WEB_SEC_HEADERS['XFO']
        response.headers['Referrer-Policy'] = config.WEB_SEC_HEADERS['RP']
        response.headers['Server'] = config.WEB_SEC_HEADERS['Server']
    return response


# Context Processors
@app.context_processor
def status():
    result = {'status': 'Ready'}
    session_state = rds.get_session_state()

    if session_state == 'created':
        result['status'] = 'Initializing...'
    elif session_state == 'running':
        progress = rds.get_scan_progress()
        result['status'] = f'Scanning... [QUEUE:{progress}]' if progress > 0 else 'Busy...'

    return result


@app.context_processor
def show_version():
    return dict(version=VERSION)


@app.context_processor
def show_frequency():
    result = {'frequency': None}
    config = rds.get_scan_config()
    if config:
        result['frequency'] = config['config']['frequency']
    return result


@app.context_processor
def show_vuln_count():
    return dict(vuln_count=len(rds.get_vuln_data()))


@app.context_processor
def inject_config_vars():
    return {
        'APP_NAME': config.APP_NAME if bool(re.match(r'^[a-zA-Z0-9 _]{,10}$', config.APP_NAME)) else 'NERVIUM',
        'APP_EXTENDED_NAME': config.APP_EXTENDED_NAME if bool(re.match(r'^[a-zA-Z0-9 _,]+$', config.APP_EXTENDED_NAME)) else '',
    }


@app.template_filter('utf8_decode')
def utf8_decode(value):
    return value.decode('utf-8') if isinstance(value, bytes) else value


if __name__ == '__main__':
    if not (config.WEB_USER or config.WEB_PASSW):
        reason = "The username or password environment variables are not set correctly."

        service_filepath = "/lib/systemd/system/nervium.service"
        if os.path.isfile(service_filepath):
            reason += f"""

If you are running NERVIUM as a systemd service,
please edit {service_filepath} in order to set valid username and password.
Once done, remember to reload and restart NERVIUM:
systemctl daemon-reload && systemctl restart nervium.service
"""

        sys.exit(reason)

    config.WEB_PASSW_HASH = generate_password_hash(config.WEB_PASSW)

    rds.initialize()
    start_workers()
    app.run(debug=config.WEB_DEBUG, host=config.WEB_HOST, port=config.WEB_PORT, threaded=True, use_evalex=False)
