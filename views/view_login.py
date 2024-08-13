from flask import Blueprint, redirect, render_template, request, session, url_for

from core.redis import rds
from core.security import verify_password
from core.utils import Utils

login = Blueprint('login', __name__, template_folder='templates')


@login.route('/login', methods=['GET', 'POST'])
def view_login():
    if request.method == 'POST':
        if rds.is_ip_blocked(request.remote_addr):
            return render_template('login.html', err='Your IP has been blocked.')

        username = request.form.get('username')
        password = request.form.get('password')

        if verify_password(username, password):
            session['session'] = username
            return redirect(url_for('index.view_index'))

        return render_template('login.html', err='Incorrect username or password. After 5 attempts, you will get blocked.')

    utils = Utils()
    msg = '' if utils.is_version_latest() else 'New Version is Available'
    return render_template('login.html', msg=msg)
