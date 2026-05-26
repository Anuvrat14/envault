"""
Dotward — Secret Scanner routes
"""
from flask import Blueprint, render_template, request, jsonify, session
from functools import wraps
import os

import scan_engine

scan_bp = Blueprint('scan', __name__)


def _require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('enc_key'):
            return jsonify({'ok': False, 'error': 'Vault is locked.'}), 401
        return f(*args, **kwargs)
    return decorated


@scan_bp.route('/scan')
def scan_page():
    if not session.get('enc_key'):
        from flask import redirect, url_for
        return redirect(url_for('auth.unlock'))
    home = os.path.expanduser('~')
    return render_template('scan.html', default_path=home)


@scan_bp.route('/scan/run', methods=['POST'])
@_require_auth
def run_scan():
    data = request.get_json(silent=True) or {}
    path = (data.get('path') or '').strip()
    mode = data.get('mode', 'all')

    if not path:
        return jsonify({'ok': False, 'error': 'No path provided.'}), 400
    if mode not in ('all', 'staged'):
        return jsonify({'ok': False, 'error': 'Invalid mode.'}), 400

    result = scan_engine.scan(path, mode)
    return jsonify(result)


@scan_bp.route('/scan/install-hook', methods=['POST'])
@_require_auth
def install_hook():
    data = request.get_json(silent=True) or {}
    repo_path = (data.get('repo_path') or '').strip()

    if not repo_path:
        return jsonify({'ok': False, 'error': 'No repo path provided.'}), 400

    result = scan_engine.install_hook(repo_path)
    return jsonify(result)
