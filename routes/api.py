"""
Dotward CLI REST API — token-authenticated, CSRF-exempt.

All endpoints require:
  • X-Dotward-Token header matching AppConfig.cli_token
  • Vault to be unlocked (enc_key present in cli_state)

Base URL: /api/v1/
"""
from __future__ import annotations

import json

from flask import Blueprint, jsonify, request

import cli_state
from crypto import decrypt_value, encrypt_value
from models import AppConfig, EnvVariable, McpAccessLog, McpRequest, Project, db
from risk_engine import analyze as risk_analyze

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

_VERSION = '1.1.0'


# --------------------------------------------------------------------------- #
# MCP access logger
# --------------------------------------------------------------------------- #

def _log_mcp(project: str, key: str, action: str) -> None:
    """Record an MCP tool access. Silently skips on any error."""
    try:
        tool = request.headers.get('X-MCP-Tool', 'mcp')
        entry = McpAccessLog(tool=tool, project=project, key=key, action=action)
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()


# --------------------------------------------------------------------------- #
# Auth helper
# --------------------------------------------------------------------------- #

def _auth() -> tuple[bytes | None, tuple[str, int] | None]:
    """
    Validate the token and return (enc_key_bytes, None) on success,
    or (None, (error_message, http_status)) on failure.
    """
    token = request.headers.get('X-Dotward-Token', '').strip()
    if not token:
        return None, ('Missing X-Dotward-Token header', 401)

    config = AppConfig.query.first()
    if not config or not config.cli_token:
        return None, ('CLI token not generated. Open Dotward → Settings → CLI Integration.', 403)

    if token != config.cli_token:
        return None, ('Invalid token', 401)

    enc_key_hex = cli_state.get_key(token)
    if enc_key_hex is None:
        return None, ('Vault is locked. Open Dotward and unlock it first.', 503)

    return bytes.fromhex(enc_key_hex), None


def _find_project(ref: str) -> Project | None:
    """Look up project by integer ID or case-insensitive name."""
    try:
        return Project.query.get(int(ref))
    except (ValueError, TypeError):
        return Project.query.filter(
            db.func.lower(Project.name) == ref.strip().lower()
        ).first()


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

@api_bp.route('/status')
def status():
    """GET /api/v1/status — check vault state."""
    enc_key, err = _auth()
    if err:
        # Special case: locked is a known state, not an auth error
        locked = (err[1] == 503)
        return jsonify({'locked': locked, 'error': err[0]}), err[1]
    return jsonify({'status': 'unlocked', 'version': _VERSION})


@api_bp.route('/projects')
def list_projects():
    """GET /api/v1/projects — list all projects."""
    enc_key, err = _auth()
    if err:
        return jsonify({'error': err[0]}), err[1]

    projects = Project.query.order_by(Project.name).all()
    return jsonify([
        {
            'id':             p.id,
            'name':           p.name,
            'description':    p.description or '',
            'variable_count': len(p.variables),
        }
        for p in projects
    ])


@api_bp.route('/projects/<project_ref>/vars')
def list_vars(project_ref):
    """GET /api/v1/projects/<name>/vars — list variable keys (no values)."""
    enc_key, err = _auth()
    if err:
        return jsonify({'error': err[0]}), err[1]

    project = _find_project(project_ref)
    if not project:
        return jsonify({'error': f'Project not found: {project_ref}'}), 404

    if not project.mcp_enabled:
        return jsonify({'error': f'MCP access disabled for project: {project.name}'}), 403

    _log_mcp(project.name, '*', 'list_keys')
    return jsonify([
        {
            'key':        v.key,
            'risk_level': v.risk_level or 'ok',
            'has_expiry': v.expires_at is not None,
        }
        for v in project.variables
    ])


@api_bp.route('/projects/<project_ref>/get/<key>')
def get_var(project_ref, key):
    """GET /api/v1/projects/<name>/get/<KEY> — decrypt and return a single value."""
    enc_key, err = _auth()
    if err:
        return jsonify({'error': err[0]}), err[1]

    project = _find_project(project_ref)
    if not project:
        return jsonify({'error': f'Project not found: {project_ref}'}), 404

    if not project.mcp_enabled:
        return jsonify({'error': f'MCP access disabled for project: {project.name}'}), 403

    var = EnvVariable.query.filter_by(project_id=project.id, key=key).first()
    if not var:
        return jsonify({'error': f'Variable not found: {key}'}), 404

    # Check if there's already an approved request we can use
    tool = request.headers.get('X-MCP-Tool', 'mcp')
    req_id = request.args.get('_req')
    if req_id:
        mcp_req = McpRequest.query.get(int(req_id))
        if mcp_req and mcp_req.status == 'approved' \
                and mcp_req.project == project.name and mcp_req.key == key:
            # Approved — decrypt and return
            try:
                value = decrypt_value(var.encrypted_value, enc_key)
            except Exception:
                return jsonify({'error': 'Decryption failed'}), 500
            _log_mcp(project.name, key, 'get_secret')
            mcp_req.status = 'used'
            db.session.commit()
            return jsonify({'key': key, 'value': value})
        elif mcp_req and mcp_req.status == 'denied':
            return jsonify({'error': 'Request denied by user'}), 403
        elif mcp_req and mcp_req.status == 'pending':
            return jsonify({'status': 'pending', 'request_id': mcp_req.id}), 202

    # No request yet — create one and ask for confirmation
    mcp_req = McpRequest(tool=tool, project=project.name, key=key, status='pending')
    db.session.add(mcp_req)
    db.session.commit()
    return jsonify({'status': 'pending', 'request_id': mcp_req.id}), 202


@api_bp.route('/projects/<project_ref>/env')
def get_env(project_ref):
    """GET /api/v1/projects/<name>/env — return all vars as {KEY: value} dict."""
    enc_key, err = _auth()
    if err:
        return jsonify({'error': err[0]}), err[1]

    project = _find_project(project_ref)
    if not project:
        return jsonify({'error': f'Project not found: {project_ref}'}), 404

    pairs: dict[str, str] = {}
    for var in project.variables:
        try:
            pairs[var.key] = decrypt_value(var.encrypted_value, enc_key)
        except Exception:
            pairs[var.key] = ''   # corrupted blob — surface empty rather than crash

    return jsonify(pairs)


@api_bp.route('/projects/<project_ref>/set/<key>', methods=['POST'])
def set_var(project_ref, key):
    """POST /api/v1/projects/<name>/set/<KEY> body: {"value": "..."} — upsert a variable."""
    enc_key, err = _auth()
    if err:
        return jsonify({'error': err[0]}), err[1]

    project = _find_project(project_ref)
    if not project:
        return jsonify({'error': f'Project not found: {project_ref}'}), 404

    data  = request.get_json(silent=True) or {}
    value = data.get('value', '')

    risk      = risk_analyze(key, value)
    encrypted = encrypt_value(value, enc_key)

    var = EnvVariable.query.filter_by(project_id=project.id, key=key).first()
    if var:
        var.encrypted_value = encrypted
        var.risk_level      = risk['level']
        var.risk_notes      = json.dumps(risk['notes'])
    else:
        var = EnvVariable(
            project_id      = project.id,
            key             = key,
            encrypted_value = encrypted,
            risk_level      = risk['level'],
            risk_notes      = json.dumps(risk['notes']),
        )
        db.session.add(var)

    db.session.commit()
    return jsonify({'key': key, 'risk_level': risk['level']}), 200
