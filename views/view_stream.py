from config import WEB_LOG_PATH
from core.security import session_required
from flask import Blueprint, Response, stream_with_context
from time import sleep

stream = Blueprint('stream', __name__, template_folder='templates')


@stream.route('/log')
@session_required
def view_stream():

    def generate():

        with open(WEB_LOG_PATH, 'r') as fd:
            while True:
                yield fd.read()
                sleep(1)

    return Response(stream_with_context(generate()), mimetype='text/plain')
