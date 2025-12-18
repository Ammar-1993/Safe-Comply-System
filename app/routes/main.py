from flask import Blueprint, render_template, current_app, jsonify, send_from_directory
import os

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def home():
    return render_template('index.html')

@main_bp.route('/<path:filename>')
def serve_pages(filename):
    if '..' in filename or filename.startswith('/'):
        return jsonify({'error': 'Not allowed'}), 403
    
    if filename.endswith('.html'):
        try:
            return render_template(filename)
        except Exception:
            return jsonify({'error': 'Not found'}), 404
            
    return jsonify({'error': 'Not found'}), 404
