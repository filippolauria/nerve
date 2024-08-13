from core.parser import SchemaParser
from core.register import Register
from core.security import session_required
from flask import Blueprint, request

scan = Blueprint('scan', __name__, template_folder='templates')


@scan.route('/scan', methods=['POST'])
@session_required
def view_scan():
    scan_data = request.get_json()
    if not isinstance(scan_data, dict):
        return {'status': 'Malformed Scan Data'}, 400

    schema = SchemaParser(scan_data, request)
    vfd, msg, scan = schema.verify()

    if not vfd:
        return {'status': f'Error: {msg}'}, 400

    register = Register()
    res, code, msg = register.scan(scan)
    return {'status': msg}, code
