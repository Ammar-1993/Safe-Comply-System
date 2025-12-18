from flask import Blueprint

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/reports', methods=['GET'])
def list_reports():
    return "Reports placeholder"
