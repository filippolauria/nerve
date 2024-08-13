from flask import Blueprint, render_template

from core.redis import rds
from core.security import session_required
from core.utils import validate_refresh_interval

assets = Blueprint('assets', __name__, template_folder='templates')


@assets.route('/assets', defaults={'refresh_interval': 0})
@assets.route('/assets/<refresh_interval>')
@session_required
def view_assets(refresh_interval):
    data = rds.get_inventory_data()
    refresh_interval = validate_refresh_interval(refresh_interval)
    return render_template('assets.html', data=data, refresh_interval=refresh_interval)
