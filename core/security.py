import config
from core.redis import rds
from flask import redirect, request, session, url_for
from flask_httpauth import HTTPBasicAuth
from functools import wraps
from werkzeug.security import check_password_hash

auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username, password):
    if rds.is_ip_blocked(request.remote_addr):
        return False

    if (username == config.WEB_USER and check_password_hash(config.WEB_PASSW_HASH, password)):
        return True

    rds.log_attempt(request.remote_addr)
    return False


def session_required(function_to_protect):
    @wraps(function_to_protect)
    def wrapper(*args, **kwargs):
        if not session.get('session'):
            return redirect(url_for('login.view_login'), 307)
        return function_to_protect(*args, **kwargs)
    return wrapper
