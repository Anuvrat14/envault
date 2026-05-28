"""
Dotward Watcher Engine — monitors AI config files and watched paths
for secrets that should be in the vault instead.

Runs as a background thread inside the Flask app.
Uses polling (no watchdog dep) — checks every 30s.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

# ── Known AI tool config paths ─────────────────────────────────────────────
def _ai_config_paths() -> list[str]:
    home = os.path.expanduser('~')
    is_win = sys.platform == 'win32'
    paths = [
        # Cursor
        os.path.join(home, '.cursor', 'mcp.json'),
        os.path.join(home, '.cursor', 'settings.json'),
        # Claude Desktop
        os.path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
        # Windows Claude Desktop
        os.path.join(os.environ.get('APPDATA', ''), 'Claude', 'claude_desktop_config.json'),
        # Continue.dev
        os.path.join(home, '.continue', 'config.json'),
        # Codeium / Windsurf
        os.path.join(home, '.codeium', 'config.json'),
        # GitHub Copilot
        os.path.join(home, '.config', 'github-copilot', 'hosts.json'),
        # OpenAI CLI
        os.path.join(home, '.openai', 'credentials'),
        # Generic .env files in common dev dirs
        os.path.join(home, 'Desktop'),
        os.path.join(home, 'Documents'),
        os.path.join(home, 'Projects'),
        os.path.join(home, 'Developer'),
        os.path.join(home, 'code'),
        os.path.join(home, 'dev'),
        os.path.join(home, 'workspace'),
    ]
    return [p for p in paths if p]


_WATCHER_INTERVAL = 30   # seconds between full scans
_running = False
_thread: threading.Thread | None = None
_app = None   # Flask app reference for app context


def start(app) -> None:
    """Start the watcher background thread."""
    global _running, _thread, _app
    if _running:
        return
    _app = app
    _running = True
    _thread = threading.Thread(target=_loop, daemon=True, name='dotward-watcher')
    _thread.start()


def stop() -> None:
    global _running
    _running = False


def _log(msg: str) -> None:
    """All watcher logging goes to stderr — stdout is reserved for MCP JSON-RPC."""
    print(f'[watcher] {msg}', file=sys.stderr, flush=True)


def _is_vault_unlocked() -> bool:
    """Check vault state. Uses in-memory cli_state when inside Flask process,
    falls back to HTTP check (for Windows subprocess edge cases)."""
    import cli_state
    if cli_state.is_unlocked():
        return True
    # Fallback: HTTP check using token file (handles subprocess context on Windows)
    try:
        import urllib.request
        token_path = os.path.join(os.path.expanduser('~'), '.dotward', 'cli_token')
        if not os.path.exists(token_path):
            return False
        with open(token_path, encoding='utf-8') as f:
            token = f.read().strip()
        if not token:
            return False
        req = urllib.request.Request('http://127.0.0.1:7331/api/v1/status')
        req.add_header('X-Dotward-Token', token)
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def _loop() -> None:
    """Main watcher loop — runs every WATCHER_INTERVAL seconds."""
    while _running:
        try:
            unlocked = _is_vault_unlocked()
            _log(f'tick — unlocked={unlocked}')
            _scan_all()
        except Exception as e:
            _log(f'scan error: {e}')
        time.sleep(_WATCHER_INTERVAL)


def _scan_all() -> None:
    """Scan all AI config paths and watched dirs for exposed secrets."""
    from dotward_cli import _SCAN_PATTERNS, _DEEP_PATTERNS, _entropy, _ASSIGN_RE, _is_binary_file

    # Only scan if vault is unlocked
    if not _is_vault_unlocked():
        _log('vault locked — skipping scan')
        return

    paths = _ai_config_paths()
    _log(f'scanning {len(paths)} paths...')
    for p in paths:
        if os.path.exists(p):
            _log(f'found: {p}')

    patterns = _SCAN_PATTERNS + _DEEP_PATTERNS
    entropy_threshold = 4.2

    for base_path in _ai_config_paths():
        if not os.path.exists(base_path):
            continue
        if os.path.isfile(base_path):
            _scan_file(base_path, patterns, entropy_threshold)
        elif os.path.isdir(base_path):
            # Only scan .env* files in watched dirs (don't recurse deeply)
            for fname in os.listdir(base_path):
                if fname.startswith('.env') and not fname.endswith('.example') \
                        and not fname.endswith('.sample') and not fname.endswith('.template'):
                    full = os.path.join(base_path, fname)
                    if os.path.isfile(full):
                        _scan_file(full, patterns, entropy_threshold)


def _scan_file(filepath: str, patterns, entropy_threshold: float) -> None:
    """Scan a single file and record any new findings."""
    from dotward_cli import _is_binary_file, _ASSIGN_RE, _entropy
    if _is_binary_file(filepath):
        return
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, PermissionError):
        return

    lines = content.splitlines()
    findings = []

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(('#', '//', '*')):
            continue
        for pat, label in patterns:
            m = pat.search(line)
            if m:
                findings.append({
                    'line': lineno,
                    'match': m.group(0)[:60],
                    'reason': label,
                })
                break
        for assign_re in _ASSIGN_RE:
            for m in assign_re.finditer(line):
                val = m.group(1)
                if _entropy(val) >= entropy_threshold and len(val) >= 20:
                    if not any(f['line'] == lineno for f in findings):
                        findings.append({
                            'line': lineno,
                            'match': val[:40],
                            'reason': f'High-entropy value — possible hardcoded secret',
                        })
                    break

    if not findings:
        return

    with _app.app_context():
        _record_findings(filepath, findings)


def _record_findings(filepath: str, findings: list[dict]) -> None:
    """Persist new findings, cross-reference against vault, skip duplicates."""
    from models import db, WatcherEvent, EnvVariable
    import cli_state

    enc_key_hex = cli_state.get_key_direct()
    vault_map: dict[str, tuple[str, str]] = {}

    if enc_key_hex:
        from crypto import decrypt_value
        enc_key = bytes.fromhex(enc_key_hex)
        try:
            for var in EnvVariable.query.all():
                try:
                    val = decrypt_value(var.encrypted_value, enc_key)
                    vault_map[val] = (var.project.name, var.key)
                except Exception:
                    pass
        except Exception:
            pass

    for f in findings:
        # Deduplicate — skip if same file+line already open
        exists = WatcherEvent.query.filter_by(
            filepath=filepath,
            line=f['line'],
            status='open'
        ).first()
        if exists:
            continue

        matched_project = None
        matched_key = None
        if f['match'] in vault_map:
            matched_project, matched_key = vault_map[f['match']]

        event = WatcherEvent(
            filepath=filepath,
            line=f['line'],
            reason=f['reason'],
            match=f['match'][:60] if f['match'] else None,
            matched_project=matched_project,
            matched_key=matched_key,
            status='open',
        )
        db.session.add(event)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
