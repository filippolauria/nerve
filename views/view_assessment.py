from flask import Blueprint, render_template
from core.security import session_required

assessment = Blueprint('assessment', __name__, template_folder='templates')


@assessment.route('/assessment')
@session_required
def view_assessment():
    return render_template('assessment.html')
