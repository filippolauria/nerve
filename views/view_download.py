from config import WEB_LOG_DIR, WEB_LOG_FILE

from core.redis import rds
from core.reports import generate_html, generate_csv, generate_txt, generate_xml
from core.security import session_required

from flask import Blueprint, flash, redirect, send_from_directory, url_for

download = Blueprint('download', __name__, template_folder='templates')


@download.route('/download/<file>')
@session_required
def view_download(file):
    if not file:
        return {'status': 'file is missing'}, 400

    if file == 'server_log':
        return send_from_directory(WEB_LOG_DIR, WEB_LOG_FILE, as_attachment=True, cache_timeout=0)

    data = rds.get_vuln_data()

    if not data:
        flash('No vulnerability data found. Ensure a scan has been performed and try again.', 'error')
        return redirect(url_for('reports.view_reports'))

    if file == 'report_html':

        conf = rds.get_scan_config()
        if not conf:
            flash('No scan configuration found. Please ensure the scan configuration is set up before generating reports.', 'error')
            return redirect(url_for('reports.view_reports'))

        report_file = generate_html(data, conf)
    elif file == 'report_txt':
        report_file = generate_txt(data)
    elif file == 'report_csv':
        report_file = generate_csv(data)
    elif file == 'report_xml':
        report_file = generate_xml(data)
    else:
        return {'status': 'file type not supported'}, 400

    return send_from_directory('reports', report_file, as_attachment=True, cache_timeout=0)
