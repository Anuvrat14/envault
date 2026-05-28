"""
Watcher routes — AI config file monitoring + MCP activity log.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
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


def _get_dotward_bin():
    """Return the dotward binary path, platform-aware."""
    home = os.path.expanduser('~')
    if sys.platform == 'win32':
        candidates = [
            os.path.join(home, '.local', 'bin', 'dotward.exe'),
            os.path.join(home, 'AppData', 'Local', 'Programs', 'dotward', 'dotward.exe'),
            os.path.join(home, '.dotward', 'bin', 'dotward.exe'),
        ]
    else:
        candidates = [
            '/usr/local/bin/dotward',
            os.path.join(home, '.dotward', 'bin', 'dotward'),
        ]
    return next((p for p in candidates if os.path.exists(p)), candidates[0])


def _find_claude_cli():
    """Find the claude CLI binary, platform-aware."""
    # shutil.which respects PATH — fastest check
    found = shutil.which('claude') or shutil.which('claude.exe')
    if found:
        return found
    home = os.path.expanduser('~')
    if sys.platform == 'win32':
        candidates = [
            os.path.join(home, '.local', 'bin', 'claude.exe'),
            os.path.join(home, 'AppData', 'Local', 'Programs', 'claude', 'claude.exe'),
        ]
    else:
        candidates = [
            '/usr/local/bin/claude',
            os.path.join(home, '.local', 'bin', 'claude'),
        ]
    return next((p for p in candidates if os.path.exists(p)), None)


def _get_config_paths():
    """Return config file paths for each AI tool, platform-aware."""
    home = os.path.expanduser('~')
    if sys.platform == 'win32':
        appdata = os.environ.get('APPDATA', os.path.join(home, 'AppData', 'Roaming'))
        return {
            'claude':      os.path.join(appdata, 'Claude', 'claude_desktop_config.json'),
            'claude-code': os.path.join(home, '.claude', 'settings.json'),
            'cursor':      os.path.join(home, '.cursor', 'mcp.json'),
            'windsurf':    os.path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
        }
    else:
        return {
            'claude':      os.path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
            'claude-code': os.path.join(home, '.claude', 'settings.json'),
            'cursor':      os.path.join(home, '.cursor', 'mcp.json'),
            'windsurf':    os.path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
        }


@watcher_bp.route('/api/mcp/connect/<tool>', methods=['POST'])
def api_mcp_connect(tool):
    """Write dotward MCP entry into the AI tool's config file."""
    err = _require_unlock()
    if err: return err

    dotward_bin = _get_dotward_bin()
    CONFIG_PATHS = _get_config_paths()

    if tool not in CONFIG_PATHS:
        return jsonify({'error': 'Unknown tool'}), 400

    # ── Claude Code CLI: use `claude mcp add` so Claude writes its own config ──
    if tool == 'claude-code':
        claude_bin = _find_claude_cli()
        if not claude_bin:
            return jsonify({'error': 'claude CLI not found. Install Claude Code first.'}), 400
        try:
            kwargs = dict(capture_output=True, text=True, timeout=15)
            if sys.platform == 'win32':
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(
                [claude_bin, 'mcp', 'add', 'dotward', '-s', 'user', '--', dotward_bin, 'mcp'],
                **kwargs
            )
            if result.returncode == 0:
                return jsonify({'ok': True,
                                'message': 'Connected! Run claude mcp list to verify, then restart Claude Code.'})
            # If already exists, that's fine too
            if 'already' in (result.stdout + result.stderr).lower():
                return jsonify({'ok': True, 'message': 'Already connected. Restart Claude Code to pick up any changes.'})
            return jsonify({'error': result.stderr or result.stdout or 'claude mcp add failed'}), 500
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Timed out running claude mcp add'}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # ── All other tools: write JSON config directly ────────────────────────
    dotward_entry = {
        'command': dotward_bin,
        'args': ['mcp']
    }

    config_path = CONFIG_PATHS[tool]
    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except Exception:
            config = {}

    if 'mcpServers' not in config:
        config['mcpServers'] = {}
    config['mcpServers']['dotward'] = dotward_entry

    try:
        # Atomic write: write to temp file then replace to avoid partial-write corruption
        tmp_path = config_path + '.tmp'
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        os.replace(tmp_path, config_path)
        label = tool.replace('-', ' ').title()
        return jsonify({'ok': True, 'path': config_path,
                        'message': f'Connected! Restart {label} to activate.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@watcher_bp.route('/api/mcp/status')
def api_mcp_status():
    """Check which AI tools are already configured."""
    CONFIG_PATHS = _get_config_paths()
    status = {}

    for name, path in CONFIG_PATHS.items():
        connected = False
        if name == 'claude-code':
            # Ask claude CLI directly — most reliable source of truth
            claude_bin = _find_claude_cli()
            if claude_bin:
                try:
                    kw = dict(capture_output=True, text=True, timeout=8)
                    if sys.platform == 'win32':
                        kw['creationflags'] = subprocess.CREATE_NO_WINDOW
                    result = subprocess.run([claude_bin, 'mcp', 'list'], **kw)
                    connected = 'dotward' in result.stdout
                except Exception:
                    pass
            # Fallback: check the settings.json file
            if not connected and os.path.exists(path):
                try:
                    with open(path, encoding='utf-8') as f:
                        cfg = json.load(f)
                    connected = 'dotward' in cfg.get('mcpServers', {})
                except Exception:
                    pass
        else:
            if os.path.exists(path):
                try:
                    with open(path, encoding='utf-8') as f:
                        cfg = json.load(f)
                    connected = 'dotward' in cfg.get('mcpServers', {})
                except Exception:
                    pass
        status[name] = connected

    status['dotward_bin'] = _get_dotward_bin()
    status['platform'] = sys.platform
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
