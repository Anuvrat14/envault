#!/usr/bin/env python3
"""
Dotward CLI — interact with your local Dotward vault from the terminal.

Requires:
  • Dotward app installed and running
  • Vault unlocked in the GUI
  • CLI token saved to ~/.dotward/cli_token (generated in Settings)

Install:
  chmod +x dotward && sudo mv dotward /usr/local/bin/dotward

Usage:
  dotward status
  dotward projects
  dotward list <project>
  dotward get <project> <KEY>
  dotward set <project> <KEY> [value]
  dotward export <project> [--output .env]
  dotward inject <project> -- <command> [args...]
  dotward scan [path] [--all]
  dotward install-hook
"""
from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DOTWARD_URL = os.environ.get('DOTWARD_URL', 'http://127.0.0.1:5177')
TOKEN_PATH  = os.path.join(os.path.expanduser('~'), '.dotward', 'cli_token')


def _token() -> str:
    """Return CLI token from env var or token file."""
    t = os.environ.get('DOTWARD_TOKEN', '').strip()
    if t:
        return t
    if not os.path.exists(TOKEN_PATH):
        _die(
            f'No CLI token found.\n\n'
            f'  1. Open Dotward and go to Settings → CLI Integration\n'
            f'  2. Click "Generate Token" then "Download Token File"\n'
            f'  3. Move the file: mv ~/Downloads/dotward_cli_token ~/.dotward/cli_token\n'
            f'  4. Set permissions: chmod 600 ~/.dotward/cli_token\n\n'
            f'Or set the DOTWARD_TOKEN environment variable.'
        )
    with open(TOKEN_PATH) as f:
        return f.read().strip()


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #

def _req(method: str, path: str, body: dict | None = None) -> dict | list:
    url  = f'{DOTWARD_URL}/api/v1{path}'
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header('X-Dotward-Token', _token())
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
            'Cannot connect to Dotward.\n\n'
            '  • Make sure the Dotward app is running\n'
            '  • Unlock the vault in the GUI\n'
            f'  • Expected at: {DOTWARD_URL}'
        )
    except Exception as e:
        _die(str(e))


def _die(msg: str) -> None:
    print(f'dotward: {msg}', file=sys.stderr)
    sys.exit(1)


def _enc(s: str) -> str:
    return quote(s, safe='')


# --------------------------------------------------------------------------- #
# Command implementations
# --------------------------------------------------------------------------- #

def cmd_status(_args: list[str]) -> None:
    """Check vault connection and state."""
    r = _req('GET', '/status')
    print(f'Dotward {r["version"]} — {r["status"]}')


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
        _die('Usage: dotward list <project>')
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
        _die('Usage: dotward get <project> <KEY>')
    result = _req('GET', f'/projects/{_enc(args[0])}/get/{_enc(args[1])}')
    print(result['value'])


def cmd_set(args: list[str]) -> None:
    """Set a variable value (reads from stdin if value omitted)."""
    if len(args) < 2:
        _die('Usage: dotward set <project> <KEY> [value]\n       (omit value to read from stdin/pipe)')
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
        _die('Usage: dotward export <project>\n       dotward export <project> --output .env')

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
        _die('Usage: dotward inject <project> -- <command> [args...]')

    sep     = args.index('--')
    project = args[0] if args else None
    cmd     = args[sep + 1:]

    if not project:
        _die('Usage: dotward inject <project> -- <command> [args...]')
    if not cmd:
        _die('No command specified after --')

    pairs  = _req('GET', f'/projects/{_enc(project)}/env')
    env    = {**os.environ, **pairs}
    result = subprocess.run(cmd, env=env)
    sys.exit(result.returncode)


# --------------------------------------------------------------------------- #
# Secret scanner (standalone — no server required)
# --------------------------------------------------------------------------- #

# Known credential regex patterns
_SCAN_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'AKIA[0-9A-Z]{16}'),                                    'AWS Access Key ID'),
    (re.compile(r'AGPA[0-9A-Z]{16}|AIPA[0-9A-Z]{16}|AROA[0-9A-Z]{16}'), 'AWS IAM Key'),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                              'Google API Key'),
    (re.compile(r'ya29\.[0-9A-Za-z\-_]+'),                               'Google OAuth Token'),
    (re.compile(r'sk-[a-zA-Z0-9]{32,}'),                                 'OpenAI / Stripe Secret Key'),
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),                            'Stripe Live Secret Key'),
    (re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),                            'Stripe Live Public Key'),
    (re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),                            'Stripe Restricted Key'),
    (re.compile(r'xox[bpas]-[0-9A-Za-z\-]{10,}'),                        'Slack Token'),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'),                                 'GitHub Personal Access Token'),
    (re.compile(r'gho_[A-Za-z0-9]{36}'),                                 'GitHub OAuth Token'),
    (re.compile(r'ghs_[A-Za-z0-9]{36}'),                                 'GitHub App Token'),
    (re.compile(r'github_pat_[A-Za-z0-9_]{82}'),                         'GitHub Fine-grained PAT'),
    (re.compile(r'npm_[A-Za-z0-9]{36}'),                                  'npm Access Token'),
    (re.compile(r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),         'SendGrid API Key'),
    (re.compile(r'key-[a-z0-9]{32}'),                                    'Mailgun API Key'),
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),   'Private Key Block'),
    (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),               'PGP Private Key'),
    (re.compile(r'eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}'), 'JWT Token'),
]

# Patterns that extract values from assignment-style lines
_ASSIGN_RE: list[re.Pattern] = [
    re.compile(r'(?:^|[^#])[A-Z][A-Z0-9_]{2,}\s*=\s*["\']?([^\s"\'#\n]{20,})["\']?', re.MULTILINE),
    re.compile(r'"(?:password|secret|token|api.?key|auth|credential|access.?key)"\s*:\s*"([^"]{8,})"', re.IGNORECASE),
    re.compile(r"'(?:password|secret|token|api.?key|auth|credential|access.?key)'\s*:\s*'([^']{8,})'", re.IGNORECASE),
]

_SKIP_DIRS  = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build', '.next', 'vendor', '.tox'}
_SKIP_EXTS  = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf',
               '.eot', '.mp4', '.mp3', '.zip', '.tar', '.gz', '.lock', '.pyc', '.exe', '.dmg'}
_SKIP_FILES = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'Pipfile.lock', 'poetry.lock'}

# Flag .env files being committed (they should never be in a repo)
_ENV_FILE_RE = re.compile(r'^\.env(\..+)?$')


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _scan_content(content: str, filename: str) -> list[dict]:
    """Scan file content and return a list of findings."""
    findings = []
    lines = content.splitlines()

    # Flag .env files being staged directly
    if _ENV_FILE_RE.match(Path(filename).name):
        findings.append({'line': 0, 'match': filename, 'reason': '.env file should never be committed — add it to .gitignore'})
        return findings

    for lineno, line in enumerate(lines, 1):
        # Skip comments and pattern-definition lines (e.g. re.compile(...))
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
            continue
        if 're.compile(' in line or 're.Pattern' in line:
            continue

        # 1 — known credential patterns
        for pattern, label in _SCAN_PATTERNS:
            m = pattern.search(line)
            if m:
                findings.append({'line': lineno, 'match': m.group(0)[:60], 'reason': label})
                break

        # 2 — high-entropy values in assignments
        for assign_re in _ASSIGN_RE:
            for m in assign_re.finditer(line):
                val = m.group(1)
                if _entropy(val) >= 4.5 and len(val) >= 20:
                    # Avoid flagging things already caught above
                    already = any(f['line'] == lineno for f in findings)
                    if not already:
                        preview = val[:40] + ('…' if len(val) > 40 else '')
                        findings.append({'line': lineno, 'match': preview, 'reason': f'High-entropy value (entropy={_entropy(val):.1f}) — possible hardcoded secret'})
                    break

    return findings


def _collect_staged_files() -> list[str]:
    """Return list of staged file paths."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
            capture_output=True, text=True, check=True
        )
        return [f for f in result.stdout.splitlines() if f.strip()]
    except subprocess.CalledProcessError:
        _die('Not inside a git repository.')
    except FileNotFoundError:
        _die('git not found — make sure git is installed.')


def _collect_all_files(root: str) -> list[str]:
    """Walk directory tree and return scannable file paths."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if fname in _SKIP_FILES:
                continue
            if Path(fname).suffix.lower() in _SKIP_EXTS:
                continue
            files.append(os.path.join(dirpath, fname))
    return files


def cmd_scan(args: list[str]) -> None:
    """
    Scan for hardcoded secrets. Works standalone — no vault/server needed.

    Usage:
      dotward scan                 scan staged files (pre-commit mode)
      dotward scan --all           scan entire working tree
      dotward scan path/to/file    scan a specific file or directory
    """
    scan_all  = '--all' in args
    targets   = [a for a in args if not a.startswith('-')]

    RED    = '\033[31m'
    YELLOW = '\033[33m'
    GREEN  = '\033[32m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

    if targets:
        # Explicit path(s)
        files = []
        for t in targets:
            p = Path(t)
            if p.is_dir():
                files.extend(_collect_all_files(str(p)))
            elif p.is_file():
                files.append(str(p))
            else:
                _die(f'Path not found: {t}')
    elif scan_all:
        files = _collect_all_files('.')
    else:
        # Default: staged files only
        files = _collect_staged_files()
        if not files:
            print(f'{GREEN}✓ No staged files to scan.{RESET}')
            return

    total_findings = 0
    scanned = 0

    for filepath in files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (OSError, PermissionError):
            continue

        scanned += 1
        findings = _scan_content(content, filepath)

        if findings:
            total_findings += len(findings)
            print(f'\n{BOLD}{RED}✗ {filepath}{RESET}')
            for hit in findings:
                loc = f'line {hit["line"]}' if hit['line'] else 'file'
                print(f'  {YELLOW}{loc}{RESET}  {hit["reason"]}')
                if hit['match'] and hit['match'] != filepath:
                    print(f'         {RED}→ {hit["match"]}{RESET}')

    print()
    if total_findings == 0:
        mode = 'staged files' if not scan_all and not targets else f'{scanned} file{"s" if scanned != 1 else ""}'
        print(f'{GREEN}✓ No secrets found in {mode}.{RESET}')
        sys.exit(0)
    else:
        print(f'{RED}{BOLD}✗ {total_findings} potential secret{"s" if total_findings != 1 else ""} found — commit blocked.{RESET}')
        print(f'  Fix the issues above before committing.')
        print(f'  If a finding is a false positive, add the line to .dotwardignore\n')
        sys.exit(1)


def cmd_install_hook(args: list[str]) -> None:
    """
    Install a git pre-commit hook that runs `dotward scan` before every commit.
    Run this once per repo.

    Usage:
      dotward install-hook
    """
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RESET = '\033[0m'

    # Find .git dir
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            capture_output=True, text=True, check=True
        )
        git_dir = result.stdout.strip()
    except subprocess.CalledProcessError:
        _die('Not inside a git repository. Run this from your project root.')
    except FileNotFoundError:
        _die('git not found.')

    hooks_dir = Path(git_dir) / 'hooks'
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / 'pre-commit'

    hook_script = """\
#!/bin/sh
# Dotward pre-commit hook
# Scans staged files for hardcoded secrets before allowing a commit.
# Installed by: dotward install-hook

if command -v dotward >/dev/null 2>&1; then
    dotward scan
    exit $?
else
    echo "dotward: CLI not found in PATH — skipping secret scan."
    echo "Install: https://github.com/Anuvrat14/dotward"
    exit 0
fi
"""

    if hook_path.exists():
        existing = hook_path.read_text()
        if 'dotward scan' in existing:
            print(f'{YELLOW}⚠ Pre-commit hook already contains dotward scan. Nothing changed.{RESET}')
            return
        # Append to existing hook instead of overwriting
        with open(hook_path, 'a') as f:
            f.write('\n# Dotward secret scan\ndotward scan\n')
        print(f'{GREEN}✓ Appended dotward scan to existing pre-commit hook: {hook_path}{RESET}')
    else:
        hook_path.write_text(hook_script)
        hook_path.chmod(0o755)
        print(f'{GREEN}✓ Pre-commit hook installed: {hook_path}{RESET}')

    print(f'  Every commit in this repo will now be scanned for hardcoded secrets.')
    print(f'  To bypass (emergency only): git commit --no-verify')


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

COMMANDS: dict[str, tuple] = {
    'status':       (cmd_status,       'Check vault connection'),
    'projects':     (cmd_projects,     'List all projects'),
    'list':         (cmd_list,         'List variable keys in a project'),
    'get':          (cmd_get,          'Print a decrypted value'),
    'set':          (cmd_set,          'Set a variable value'),
    'export':       (cmd_export,       'Export variables as KEY=VALUE'),
    'inject':       (cmd_inject,       'Run a command with vars injected'),
    'scan':         (cmd_scan,         'Scan for hardcoded secrets (no vault needed)'),
    'install-hook': (cmd_install_hook, 'Install git pre-commit hook for this repo'),
}

USAGE = """\
\033[1mDotward CLI\033[0m — encrypted vault + secret scanner

\033[1mVault commands\033[0m (vault must be running + unlocked):
  dotward status
  dotward projects
  dotward list     <project>
  dotward get      <project> <KEY>
  dotward set      <project> <KEY> [value]
  dotward export   <project> [--output .env]
  dotward inject   <project> -- <command> [args...]

\033[1mSecret scanner\033[0m (standalone — no vault needed):
  dotward scan                  scan staged files before commit
  dotward scan --all            scan entire working tree
  dotward scan <path>           scan a specific file or directory
  dotward install-hook          install git pre-commit hook in this repo

\033[1mExamples:\033[0m
  dotward get "My App" DATABASE_URL
  dotward inject "My App" -- npm run dev
  dotward export "My App" --output .env
  dotward scan --all
  dotward install-hook

\033[1mEnvironment variables:\033[0m
  DOTWARD_TOKEN    Override the CLI token
  DOTWARD_URL      Override server URL (default: http://127.0.0.1:5177)

\033[1mToken setup:\033[0m
  Dotward → Settings → CLI Integration → Generate Token → Download
  mv ~/Downloads/dotward_cli_token ~/.dotward/cli_token
  chmod 600 ~/.dotward/cli_token"""


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help', 'help'):
        print(USAGE)
        return

    cmd = args[0]
    if cmd not in COMMANDS:
        print(f'dotward: unknown command "{cmd}"', file=sys.stderr)
        print('Run "dotward --help" for usage.', file=sys.stderr)
        sys.exit(1)

    COMMANDS[cmd][0](args[1:])


if __name__ == '__main__':
    main()
