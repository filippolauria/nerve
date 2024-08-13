from core.parser import SchemaParser
from core.redis import rds
from core.register import Register
from core.security import auth

from flask import request
from flask_restful import Resource


class Scan(Resource):
    @auth.login_required
    def get(self, action=None):
        if not action:
            return {'status': 'action type is missing'}, 400

        if action != 'status':
            return {'status': 'unsupported action'}, 400

        state = rds.get_session_state()

        if not state:
            state = 'idle'

        data = rds.get_vuln_data()
        cfg = rds.get_scan_config()

        return {'status': state, 'vulnerabilities': data, 'scan_config': cfg}

    @auth.login_required
    def put(self, action=None):
        if action == 'reset':
            rds.clear_session()
            return {'status': 'flushed scan state'}

        return {'status': 'unsupported action'}, 400

    @auth.login_required
    def post(self, action=None):
        scan = request.get_json()
        register = Register()

        if scan and isinstance(scan, dict):
            schema = SchemaParser(scan, request)
            vfd, msg, scan = schema.verify()
            if not vfd:
                return {'status': 'Error: ' + msg}, 400
        else:
            return {'status': 'Malformed Scan Data'}, 400

        res, code, msg = register.scan(scan)

        return {'status': msg}, code
