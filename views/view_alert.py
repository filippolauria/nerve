from flask import Blueprint, flash, redirect, render_template, url_for

from core.redis import rds
from core.security import session_required

alert = Blueprint('alert', __name__, template_folder='templates')


@alert.route('/alert/view/<alert_id>')
@session_required
def view_alert(alert_id):
    vuln = rds.get_vuln_by_id(alert_id)
    if vuln:
        return render_template('alert.html', vuln={'key': alert_id, 'data': vuln})

    flash('Could not display alert.', 'error')
    return redirect(url_for('vulnerabilities.view_vulns'))


@alert.route('/alert/resolve/<alert_id>')
@session_required
def view_resolve_alert(alert_id):
    if not rds.get_vuln_by_id(alert_id):
        message = 'Could not resolve alert.'
        category = 'error'
    else:
        rds.delete(alert_id)
        message = 'Resolved alert successfully.'
        category = 'success'

    flash(message, category)
    return redirect(url_for('vulnerabilities.view_vulns'))
