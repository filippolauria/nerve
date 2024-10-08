from core.redis import rds
from core.security import auth

from flask import request
from flask_restful import Resource


class Exclusion(Resource):
    @auth.login_required
    def get(self):
        exclusions = rds.get_exclusions()
        return {'exclusions': exclusions}, 200

    @auth.login_required
    def post(self):
        user_exclusions = request.get_json()
        if isinstance(user_exclusions, dict):
            rds.store_json('p_rule-exclusions', user_exclusions)
            return {'status': 'ok'}
        return {'status': 'Malformed data, must be JSON'}
