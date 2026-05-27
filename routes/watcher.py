"""
Watcher routes — AI config file monitoring + MCP activity log.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request, session

import cli_state
from models import McpAccessLog, WatcherEvent, db

watcher_bp = Blueprint('watcher', __name__)


def _require_unlock():
    if not session.get('unlocked'):
        return jsonify({'error': 'Vault locked'}), 403
    return None


# ── Pages ──────────────────────────────────────────────────────────────────

@watcher_bp.route('/watcher')
def watcher_page():
    if not session.get('unlocked'):
        from flask import redirect, url_for
        return redirect(url_for('auth.unlock'))
    open_events  = WatcherEvent.query.filter_by(status='open').order_by(WatcherEvent.created_at.desc()).limit(100).all()
    fixed_events = WatcherEvent.query.filter(WatcherEvent.status != 'open').order_by(WatcherEvent.created_at.desc()).limit(50).all()
    mcp_logs     = McpAccessLog.query.order_by(McpAccessLog.created_at.desc()).limit(50).all()
    return render_template('watcher.html',
                           open_events=open_events,
                           fixed_events=fixed_events,
                           mcp_logs=mcp_logs)


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
    """Quick badge count for navbar."""
    count = WatcherEvent.query.filter_by(status='open').count()
    return jsonify({'count': count})


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
