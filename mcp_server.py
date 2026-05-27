"""
Dotward MCP Server — exposes vault secrets to AI tools (Cursor, Claude Desktop)
via the Model Context Protocol over stdio.

Usage (added to AI tool's mcp config):
  {
    "mcpServers": {
      "dotward": {
        "command": "dotward",
        "args": ["mcp"]
      }
    }
  }

Security model:
  - Vault must be unlocked in the Dotward app
  - Per-request token auth via ~/.dotward/cli_token
  - Every access is logged to mcp_access_log table
  - If vault is locked, all tool calls return an error — nothing leaks
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

DOTWARD_URL = os.environ.get('DOTWARD_URL', 'http://127.0.0.1:7331')
TOKEN_PATH  = os.path.join(os.path.expanduser('~'), '.dotward', 'cli_token')

MCP_VERSION = '2024-11-05'


def _token() -> str | None:
    t = os.environ.get('DOTWARD_TOKEN', '').strip()
    if t:
        return t
    if os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH) as f:
            return f.read().strip()
    return None


def _api(method: str, path: str, body: dict | None = None):
    token = _token()
    if not token:
        raise RuntimeError('No CLI token found. Generate one in Dotward → Settings → CLI Integration.')
    url  = f'{DOTWARD_URL}/api/v1{path}'
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header('X-Dotward-Token', token)
    req.add_header('X-MCP-Client', 'true')
    if data:
        req.add_header('Content-Type', 'application/json')
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + '\n')
    sys.stdout.flush()


def _error(id, code: int, message: str) -> None:
    _send({'jsonrpc': '2.0', 'id': id, 'error': {'code': code, 'message': message}})


def _result(id, result) -> None:
    _send({'jsonrpc': '2.0', 'id': id, 'result': result})


# ── Tool definitions ───────────────────────────────────────────────────────

TOOLS = [
    {
        'name': 'list_projects',
        'description': 'List all projects in the Dotward vault. Returns project names only — no secret values.',
        'inputSchema': {
            'type': 'object',
            'properties': {},
            'required': [],
        },
    },
    {
        'name': 'get_secret',
        'description': (
            'Get a decrypted secret value from the Dotward vault. '
            'The vault must be unlocked in the Dotward app. '
            'Every access is logged.'
        ),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'project': {'type': 'string', 'description': 'Project name (case-insensitive)'},
                'key':     {'type': 'string', 'description': 'Variable key name e.g. STRIPE_KEY'},
            },
            'required': ['project', 'key'],
        },
    },
    {
        'name': 'list_keys',
        'description': 'List all variable key names in a project (no values).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'project': {'type': 'string', 'description': 'Project name'},
            },
            'required': ['project'],
        },
    },
]


# ── Request handlers ───────────────────────────────────────────────────────

def handle_initialize(req_id, params):
    _result(req_id, {
        'protocolVersion': MCP_VERSION,
        'capabilities': {'tools': {}},
        'serverInfo': {'name': 'dotward', 'version': '1.0.0'},
    })


def handle_tools_list(req_id, params):
    _result(req_id, {'tools': TOOLS})


def handle_tools_call(req_id, params):
    name  = params.get('name', '')
    args  = params.get('arguments', {})

    try:
        if name == 'list_projects':
            data = _api('GET', '/projects')
            names = [p['name'] for p in data]
            _result(req_id, {
                'content': [{'type': 'text', 'text': '\n'.join(names) or 'No projects found.'}]
            })

        elif name == 'get_secret':
            project = args.get('project', '').strip()
            key     = args.get('key', '').strip()
            if not project or not key:
                _error(req_id, -32602, 'project and key are required')
                return
            from urllib.parse import quote
            data = _api('GET', f'/projects/{quote(project, safe="")}/get/{quote(key, safe="")}')
            _result(req_id, {
                'content': [{'type': 'text', 'text': data.get('value', '')}]
            })

        elif name == 'list_keys':
            project = args.get('project', '').strip()
            if not project:
                _error(req_id, -32602, 'project is required')
                return
            from urllib.parse import quote
            data = _api('GET', f'/projects/{quote(project, safe="")}/vars')
            keys = [v['key'] for v in data]
            _result(req_id, {
                'content': [{'type': 'text', 'text': '\n'.join(keys) or 'No variables found.'}]
            })

        else:
            _error(req_id, -32601, f'Unknown tool: {name}')

    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            msg = json.loads(body).get('error', str(e))
        except Exception:
            msg = str(e)
        _error(req_id, -32000, f'Vault error: {msg}')
    except ConnectionRefusedError:
        _error(req_id, -32000, 'Dotward is not running. Open the app and unlock the vault first.')
    except RuntimeError as e:
        _error(req_id, -32000, str(e))
    except Exception as e:
        _error(req_id, -32000, str(e))


# ── Main stdio loop ────────────────────────────────────────────────────────

def run() -> None:
    """Run MCP server over stdio. Called by `dotward mcp`."""
    import logging
    logging.disable(logging.CRITICAL)   # silence all logs — MCP uses stdout

    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            req = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        req_id = req.get('id')
        method = req.get('method', '')
        params = req.get('params', {})

        if method == 'initialize':
            handle_initialize(req_id, params)
        elif method == 'tools/list':
            handle_tools_list(req_id, params)
        elif method == 'tools/call':
            handle_tools_call(req_id, params)
        elif method == 'notifications/initialized':
            pass   # no-op
        elif req_id is not None:
            _error(req_id, -32601, f'Method not found: {method}')
