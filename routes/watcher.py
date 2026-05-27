"""
Watcher routes — AI config file monitoring + MCP activity log.
"""
from __future__ import annotations

import json
import os
import sys

from flask import Blueprint, jsonify, render_template, request, session

import cli_state
from models import McpAccessLog, McpRequest, Project, WatcherEvent, db

watcher_bp = Blueprint('watcher', __name__)


def _require_unlock():
    if not session.get('enc_key'):
        return jsonify({'error': 'Vault locked'}), 403
    return None


# ── Pages ──────────────────────────────────────────────────────────────────

@watcher_bp.route('/watcher')
def watcher_page():
    if not session.get('enc_key'):
        from flask import redirect, url_for
        return redirect(url_for('projects.dashboard'))
    open_events  = WatcherEvent.query.filter_by(status='open').order_by(WatcherEvent.created_at.desc()).limit(100).all()
    fixed_events = WatcherEvent.query.filter(WatcherEvent.status != 'open').order_by(WatcherEvent.created_at.desc()).limit(50).all()
    mcp_logs     = McpAccessLog.query.order_by(McpAccessLog.created_at.desc()).limit(50).all()
    projects     = Project.query.order_by(Project.name).all()
    return render_template('watcher.html',
                           open_events=open_events,
                           fixed_events=fixed_events,
                           mcp_logs=mcp_logs,
                           projects=projects)


# ── API ────────────────────────────────────────────────────────────────────

@watcher_bp.route('/api/watcher/events')
def api_events():
    err = _require_unlock()
    if err: return err
    events = WatcherEvent.query.filter_by(status='open').order_by(WatcherEvent.created_at.desc()).limit(100).all()
    return jsonify([{
        'id':              e.id,
        'filepath':        e.filepath,
        'line':            e.line,
        'reason':          e.reason,
        'match':           e.match,
        'matched_project': e.matched_project,
        'matched_key':     e.matched_key,
        'status':          e.status,
        'created_at':      e.created_at.isoformat(),
    } for e in events])


@watcher_bp.route('/api/watcher/events/<int:event_id>/dismiss', methods=['POST'])
def api_dismiss(event_id: int):
    err = _require_unlock()
    if err: return err
    e = WatcherEvent.query.get_or_404(event_id)
    e.status = 'dismissed'
    db.session.commit()
    return jsonify({'ok': True})


@watcher_bp.route('/api/watcher/events/<int:event_id>/fix', methods=['POST'])
def api_fix(event_id: int):
    """Mark event as fixed (user has moved the secret to vault manually)."""
    err = _require_unlock()
    if err: return err
    e = WatcherEvent.query.get_or_404(event_id)
    e.status = 'fixed'
    db.session.commit()
    return jsonify({'ok': True})


@watcher_bp.route('/api/watcher/count')
def api_count():
    """Quick badge count for navbar — includes pending MCP requests."""
    alert_count = WatcherEvent.query.filter_by(status='open').count()
    mcp_count   = McpRequest.query.filter_by(status='pending').count()
    return jsonify({'count': alert_count + mcp_count})


@watcher_bp.route('/api/mcp/requests')
def api_mcp_requests():
    err = _require_unlock()
    if err: return err
    reqs = McpRequest.query.filter_by(status='pending').order_by(McpRequest.created_at.desc()).all()
    return jsonify([{
        'id':         r.id,
        'tool':       r.tool,
        'project':    r.project,
        'key':        r.key,
        'status':     r.status,
        'created_at': r.created_at.isoformat(),
    } for r in reqs])


@watcher_bp.route('/api/mcp/requests/<int:req_id>/approve', methods=['POST'])
def api_mcp_approve(req_id):
    err = _require_unlock()
    if err: return err
    r = McpRequest.query.get_or_404(req_id)
    r.status = 'approved'
    db.session.commit()
    return jsonify({'ok': True})


@watcher_bp.route('/api/mcp/requests/<int:req_id>/deny', methods=['POST'])
def api_mcp_deny(req_id):
    err = _require_unlock()
    if err: return err
    r = McpRequest.query.get_or_404(req_id)
    r.status = 'denied'
    db.session.commit()
    return jsonify({'ok': True})


@watcher_bp.route('/api/projects/<int:project_id>/mcp-toggle', methods=['POST'])
def api_mcp_toggle(project_id):
    err = _require_unlock()
    if err: return err
    p = Project.query.get_or_404(project_id)
    p.mcp_enabled = not p.mcp_enabled
    db.session.commit()
    return jsonify({'ok': True, 'mcp_enabled': p.mcp_enabled})


@watcher_bp.route('/api/mcp/connect/<tool>', methods=['POST'])
def api_mcp_connect(tool):
    """Write dotward MCP entry into the AI tool's config file."""
    err = _require_unlock()
    if err: return err

    home = os.path.expanduser('~')

    # Find where syncCLI actually installed the binary
    candidates = [
        '/usr/local/bin/dotward',
        os.path.join(home, '.dotward', 'bin', 'dotward'),
    ]
    dotward_bin = next((p for p in candidates if os.path.exists(p)), candidates[0])

    dotward_entry = {
        'command': dotward_bin,
        'args': ['mcp']
    }

    CONFIG_PATHS = {
        'claude': os.path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
        'cursor': os.path.join(home, '.cursor', 'mcp.json'),
    }

    if tool not in CONFIG_PATHS:
        return jsonify({'error': 'Unknown tool'}), 400

    config_path = CONFIG_PATHS[tool]
    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    # Load existing config or start fresh
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                config = json.load(f)
        except Exception:
            config = {}

    # Merge in dotward entry
    if 'mcpServers' not in config:
        config['mcpServers'] = {}
    config['mcpServers']['dotward'] = dotward_entry

    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        return jsonify({'ok': True, 'path': config_path,
                        'message': f'Connected! Restart {tool.capitalize()} to activate.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@watcher_bp.route('/api/mcp/status')
def api_mcp_status():
    """Check which AI tools are already configured."""
    home = os.path.expanduser('~')
    tools = {
        'claude': os.path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
        'cursor': os.path.join(home, '.cursor', 'mcp.json'),
    }
    status = {}
    for name, path in tools.items():
        connected = False
        if os.path.exists(path):
            try:
                with open(path) as f:
                    cfg = json.load(f)
                connected = 'dotward' in cfg.get('mcpServers', {})
            except Exception:
                pass
        status[name] = connected

    # Also return the actual binary path so the UI can show it
    candidates = [
        '/usr/local/bin/dotward',
        os.path.join(home, '.dotward', 'bin', 'dotward'),
    ]
    dotward_bin = next((p for p in candidates if os.path.exists(p)), candidates[0])
    status['dotward_bin'] = dotward_bin
    return jsonify(status)


@watcher_bp.route('/api/mcp/logs')
def api_mcp_logs():
    err = _require_unlock()
    if err: return err
    logs = McpAccessLog.query.order_by(McpAccessLog.created_at.desc()).limit(50).all()
    return jsonify([{
        'id':         l.id,
        'tool':       l.tool,
        'project':    l.project,
        'key':        l.key,
        'action':     l.action,
        'created_at': l.created_at.isoformat(),
    } for l in logs])
