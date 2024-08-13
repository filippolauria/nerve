import config

from copy import deepcopy
from core.logging import logger
from core.parser import SchemaParser
from core.register import Register
from core.security import session_required

from flask import Blueprint, flash, redirect, render_template, request, url_for

qs = Blueprint('qs', __name__, template_folder='templates')


def render_quickstart(message=None, status='error', reload=False):
    if message is not None:
        flash(message, status)

    return redirect(url_for('qs.view_qs')) if reload else render_template('quickstart.html')


@qs.route('/qs', methods=['GET', 'POST'])
@session_required
def view_qs():
    if request.method != 'POST':
        return render_quickstart()

    network = request.values.get('network')
    if not network:
        return render_quickstart(message='A valid address must be specified')

    scan = deepcopy(config.DEFAULT_SCAN)
    scan['targets']['networks'].append(network)

    schema = SchemaParser(scan, request)
    vfd, msg, scan = schema.verify()

    if not vfd:
        return render_quickstart(message=msg)

    register = Register()
    res, code, msg = register.scan(scan)
    if not res:
        return render_quickstart(message=msg)

    logger.info('A scan was initiated')
    return render_quickstart(message='Assessment started.', status='success', reload=True)
