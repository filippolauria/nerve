from core.redis import rds
from core.security import session_required
from flask import Blueprint, flash, redirect, url_for

startover = Blueprint('startover', __name__, template_folder='templates')


@startover.route('/startover')
@session_required
def view_startover():
    rds.clear_session()
    flash('Rolled back successfully', 'success')
    return redirect(url_for('dashboard.view_dashboard'), 301)
