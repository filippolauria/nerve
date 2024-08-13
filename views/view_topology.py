from flask import Blueprint, render_template

from core.security import session_required
from core.redis import rds
from core.utils import validate_refresh_interval

topology = Blueprint('topology', __name__, template_folder='templates')


@topology.route('/topology', defaults={'refresh_interval': 0})
@topology.route('/topology/<refresh_interval>')
@session_required
def view_topology(refresh_interval):
    data = rds.get_topology()
    vulns = rds.get_vuln_data()
    refresh_interval = validate_refresh_interval(refresh_interval)
    return render_template('topology.html', data=data, vulns=vulns, refresh_interval=refresh_interval)
