#!/usr/bin/env python3
"""
Envault CLI — interact with your local Envault vault from the terminal.

Requires:
  • Envault app installed and running
  • Vault unlocked in the GUI
  • CLI token saved to ~/.envault/cli_token (generated in Settings)

Install:
  chmod +x envault && sudo mv envault /usr/local/bin/envault

Usage:
  envault status
  envault projects
  envault list <project>
  envault get <project> <KEY>
  envault set <project> <KEY> [value]
  envault export <project> [--output .env]
  envault inject <project> -- <command> [args...]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import quote

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

ENVAULT_URL = os.environ.get('ENVAULT_URL', 'http://127.0.0.1:5177')
TOKEN_PATH  = os.path.join(os.path.expanduser('~'), '.envault', 'cli_token')


def _token() -> str:
    """Return CLI token from env var or token file."""
    t = os.environ.get('ENVAULT_TOKEN', '').strip()
    if t:
        return t
    if not os.path.exists(TOKEN_PATH):
        _die(
            f'No CLI token found.\n\n'
            f'  1. Open Envault and go to Settings → CLI Integration\n'
            f'  2. Click "Generate Token" then "Download Token File"\n'
            f'  3. Move the file: mv ~/Downloads/envault_cli_token ~/.envault/cli_token\n'
            f'  4. Set permissions: chmod 600 ~/.envault/cli_token\n\n'
            f'Or set the ENVAULT_TOKEN environment variable.'
        )
    with open(TOKEN_PATH) as f:
        return f.read().strip()


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #

def _req(method: str, path: str, body: dict | None = None) -> dict | list:
    url  = f'{ENVAULT_URL}/api/v1{path}'
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header('X-Envault-Token', _token())
    if data:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_bytes = e.read()
        try:
            msg = json.loads(body_bytes).get('error', str(e))
        except Exception:
            msg = str(e)
        _die(msg)
    except ConnectionRefusedError:
        _die(
            'Cannot connect to Envault.\n\n'
            '  • Make sure the Envault app is running\n'
            '  • Unlock the vault in the GUI\n'
            f'  • Expected at: {ENVAULT_URL}'
        )
    except Exception as e:
        _die(str(e))


def _die(msg: str) -> None:
    print(f'envault: {msg}', file=sys.stderr)
    sys.exit(1)


def _enc(s: str) -> str:
    return quote(s, safe='')


# --------------------------------------------------------------------------- #
# Command implementations
# --------------------------------------------------------------------------- #

def cmd_status(_args: list[str]) -> None:
    """Check vault connection and state."""
    r = _req('GET', '/status')
    print(f'Envault {r["version"]} — {r["status"]}')


def cmd_projects(_args: list[str]) -> None:
    """List all projects."""
    projects = _req('GET', '/projects')
    if not projects:
        print('No projects found.')
        return
    name_w = max(len(p['name']) for p in projects) + 2
    for p in projects:
        n     = p['variable_count']
        desc  = f'  {p["description"]}' if p.get('description') else ''
        print(f'  {p["name"]:<{name_w}} {n} var{"s" if n != 1 else ""}{desc}')


def cmd_list(args: list[str]) -> None:
    """List variable keys in a project."""
    if not args:
        _die('Usage: envault list <project>')
    variables = _req('GET', f'/projects/{_enc(args[0])}/vars')
    if not variables:
        print('No variables found.')
        return
    for v in variables:
        risk = v.get('risk_level', 'ok')
        tag  = f'  \033[33m[{risk}]\033[0m' if risk not in ('ok', 'none', '', None) else ''
        print(f'  {v["key"]}{tag}')


def cmd_get(args: list[str]) -> None:
    """Print a single decrypted value."""
    if len(args) < 2:
        _die('Usage: envault get <project> <KEY>')
    result = _req('GET', f'/projects/{_enc(args[0])}/get/{_enc(args[1])}')
    print(result['value'])


def cmd_set(args: list[str]) -> None:
    """Set a variable value (reads from stdin if value omitted)."""
    if len(args) < 2:
        _die('Usage: envault set <project> <KEY> [value]\n       (omit value to read from stdin/pipe)')
    project, key = args[0], args[1]
    if len(args) >= 3:
        value = args[2]
    elif not sys.stdin.isatty():
        value = sys.stdin.read().rstrip('\n')
    else:
        import getpass
        value = getpass.getpass(f'Value for {key}: ')

    result = _req('POST', f'/projects/{_enc(project)}/set/{_enc(key)}', {'value': value})
    risk   = result.get('risk_level', 'ok')
    if risk not in ('ok', 'none', '', None):
        print(f'Set {key}  \033[33m({risk} risk detected)\033[0m')
    else:
        print(f'Set {key}')


def cmd_export(args: list[str]) -> None:
    """Export all variables as KEY=VALUE lines."""
    if not args:
        _die('Usage: envault export <project>\n       envault export <project> --output .env')

    project = args[0]
    output  = None
    if '--output' in args:
        idx = args.index('--output')
        output = args[idx + 1] if idx + 1 < len(args) else None

    pairs = _req('GET', f'/projects/{_enc(project)}/env')
    lines = '\n'.join(f'{k}={v}' for k, v in sorted(pairs.items())) + '\n'

    if output:
        with open(output, 'w') as f:
            f.write(lines)
        print(f'Exported {len(pairs)} variable{"s" if len(pairs) != 1 else ""} → {output}')
    else:
        sys.stdout.write(lines)


def cmd_inject(args: list[str]) -> None:
    """Run a command with vault variables injected as environment variables."""
    if '--' not in args or not args:
        _die('Usage: envault inject <project> -- <command> [args...]')

    sep     = args.index('--')
    project = args[0] if args else None
    cmd     = args[sep + 1:]

    if not project:
        _die('Usage: envault inject <project> -- <command> [args...]')
    if not cmd:
        _die('No command specified after --')

    pairs  = _req('GET', f'/projects/{_enc(project)}/env')
    env    = {**os.environ, **pairs}
    result = subprocess.run(cmd, env=env)
    sys.exit(result.returncode)


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

COMMANDS: dict[str, tuple] = {
    'status':   (cmd_status,   'Check vault connection'),
    'projects': (cmd_projects, 'List all projects'),
    'list':     (cmd_list,     'List variable keys in a project'),
    'get':      (cmd_get,      'Print a decrypted value'),
    'set':      (cmd_set,      'Set a variable value'),
    'export':   (cmd_export,   'Export variables as KEY=VALUE'),
    'inject':   (cmd_inject,   'Run a command with vars injected'),
}

USAGE = """\
\033[1mEnvault CLI\033[0m — interact with your local encrypted vault

\033[1mUsage:\033[0m
  envault status
  envault projects
  envault list     <project>
  envault get      <project> <KEY>
  envault set      <project> <KEY> [value]
  envault export   <project> [--output .env]
  envault inject   <project> -- <command> [args...]

\033[1mExamples:\033[0m
  envault get "My App" DATABASE_URL
  envault set "My App" API_KEY sk-abc123
  cat secret.txt | envault set "My App" PRIVATE_KEY
  envault inject "My App" -- npm run dev
  envault export "My App" --output .env

\033[1mEnvironment variables:\033[0m
  ENVAULT_TOKEN    Override the CLI token
  ENVAULT_URL      Override server URL (default: http://127.0.0.1:5177)

\033[1mToken setup:\033[0m
  Envault → Settings → CLI Integration → Generate Token → Download
  mv ~/Downloads/envault_cli_token ~/.envault/cli_token
  chmod 600 ~/.envault/cli_token"""


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help', 'help'):
        print(USAGE)
        return

    cmd = args[0]
    if cmd not in COMMANDS:
        print(f'envault: unknown command "{cmd}"', file=sys.stderr)
        print('Run "envault --help" for usage.', file=sys.stderr)
        sys.exit(1)

    COMMANDS[cmd][0](args[1:])


if __name__ == '__main__':
    main()
