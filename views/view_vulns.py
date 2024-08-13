from flask import Blueprint, render_template

from core.security import session_required
from core.redis import rds
from core.utils import validate_refresh_interval

vulns = Blueprint('vulnerabilities', __name__, template_folder='templates')


@vulns.route('/vulnerabilities', defaults={'refresh_interval': 0})
@vulns.route('/vulnerabilities/<refresh_interval>')
@session_required
def view_vulns(refresh_interval):
    data = rds.get_vuln_data()
    if data:
        data = {
            k: v
            for k, v in sorted(
                data.items(),
                key=lambda item: item[1]['rule_sev'],
                reverse=True
            )
        }

    refresh_interval = validate_refresh_interval(refresh_interval)

    return render_template('vulnerabilities.html', data=data, refresh_interval=refresh_interval)
