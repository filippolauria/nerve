from core.security import session_required
from flask import Blueprint, flash, redirect, session, url_for

logout = Blueprint('logout', __name__, template_folder='templates')


@logout.route('/logout')
@session_required
def view_logout():
    if session.get('session'):
        session.pop('session')

    flash('Logged out successfully', 'success')

    return redirect(url_for('login.view_login'))
