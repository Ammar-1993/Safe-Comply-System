from flask import Blueprint, send_from_directory, current_app, jsonify
import os

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def home():
    return send_from_directory('app/templates', 'index.html')

@main_bp.route('/<path:filename>')
def serve_static_file(filename):
    # Serve static files from root (for backward compatibility during refactor)
    # Ideally these should be in app/static
    if '..' in filename or filename.startswith('/'):
        return jsonify({'error': 'Not allowed'}), 403
    
    # Check if it's in templates (html)
    if filename.endswith('.html'):
        return send_from_directory('app/templates', filename)
    
    # Check if it's in static
    # This part is tricky because we moved css/js to subfolders.
    # We might need a smarter static file server or update the HTML.
    # For now, let's try to find it.
    
    return jsonify({'error': 'Not found'}), 404
