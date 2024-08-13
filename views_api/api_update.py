from core.security import auth
from core.utils import Utils

from flask_restful import Resource


class Update(Resource):
    @auth.login_required
    def get(self, component=None):
        if not component:
            return {'status': 'Component is missing'}, 400

        if component != 'platform':
            return {'status': 'unsupported action'}, 400

        utils = Utils()
        status = 'system is up to date' if utils.is_version_latest() else 'updates are available'
        return {'status': status}
