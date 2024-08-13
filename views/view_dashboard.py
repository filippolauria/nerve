from flask import Blueprint, render_template

from core.redis import rds
from core.security import session_required
from core.utils import Charts

dashboard = Blueprint('dashboard', __name__, template_folder='templates')


@dashboard.route('/dashboard')
@session_required
def view_dashboard():
    chart = Charts()

    networks, domains = [], []
    cfg = rds.get_scan_config()
    if cfg:
        networks = cfg['targets']['networks']
        domains = cfg['targets']['domains']

    hosts = rds.get_topology()
    vulns = rds.get_vuln_data()

    return render_template(
        'dashboard.html',
        hosts=hosts,
        networks=networks,
        last_scan=rds.get_last_scan(),
        scan_count=rds.get_scan_count(),
        domains=domains,
        vulns=vulns,
        chart=chart.make_doughnut(vulns),
        radar=chart.make_radar(vulns)
    )
