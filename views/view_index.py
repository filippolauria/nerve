from flask import Blueprint, make_response, redirect, render_template, request, url_for

from core.security import session_required

index = Blueprint('index', __name__, template_folder='templates')


@index.route('/')
@session_required
def view_index():
    if 'toggle_welcome' not in request.cookies:
        response = make_response(render_template('welcome.html'))
        response.set_cookie('toggle_welcome', 'true')
        return response

    return redirect(url_for('dashboard.view_dashboard'))
