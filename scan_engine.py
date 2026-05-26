"""
Dotward Scan Engine
Standalone secret scanner — no vault or server required.
Used by both the Flask UI (routes/scan.py) and the CLI (dotward_cli.py).
"""
from __future__ import annotations

import math
import os
import re
import subprocess
from pathlib import Path

# ── Known credential patterns ──────────────────────────────────────────────

PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'AKIA[0-9A-Z]{16}'),                                     'AWS Access Key ID'),
    (re.compile(r'AGPA[0-9A-Z]{16}|AIPA[0-9A-Z]{16}|AROA[0-9A-Z]{16}'),  'AWS IAM Key'),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                               'Google API Key'),
    (re.compile(r'ya29\.[0-9A-Za-z\-_]+'),                                'Google OAuth Token'),
    (re.compile(r'sk-[a-zA-Z0-9]{32,}'),                                  'OpenAI / Stripe Secret Key'),
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),                             'Stripe Live Secret Key'),
    (re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),                             'Stripe Live Public Key'),
    (re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),                             'Stripe Restricted Key'),
    (re.compile(r'xox[bpas]-[0-9A-Za-z\-]{10,}'),                         'Slack Token'),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'),                                  'GitHub Personal Access Token'),
    (re.compile(r'gho_[A-Za-z0-9]{36}'),                                  'GitHub OAuth Token'),
    (re.compile(r'ghs_[A-Za-z0-9]{36}'),                                  'GitHub App Token'),
    (re.compile(r'github_pat_[A-Za-z0-9_]{82}'),                          'GitHub Fine-grained PAT'),
    (re.compile(r'npm_[A-Za-z0-9]{36}'),                                   'npm Access Token'),
    (re.compile(r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),          'SendGrid API Key'),
    (re.compile(r'key-[a-z0-9]{32}'),                                     'Mailgun API Key'),
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),    'Private Key Block'),
    (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),                'PGP Private Key'),
    (re.compile(
        r'eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}'
    ), 'JWT Token'),
]

# ── Assignment-style value extractors ─────────────────────────────────────

_ASSIGN_RE: list[re.Pattern] = [
    re.compile(r'(?:^|[^#])[A-Z][A-Z0-9_]{2,}\s*=\s*["\']?([^\s"\'#\n]{20,})["\']?', re.MULTILINE),
    re.compile(r'"(?:password|secret|token|api.?key|auth|credential|access.?key)"\s*:\s*"([^"]{8,})"', re.IGNORECASE),
    re.compile(r"'(?:password|secret|token|api.?key|auth|credential|access.?key)'\s*:\s*'([^']{8,})'", re.IGNORECASE),
]

# ── Skip lists ─────────────────────────────────────────────────────────────

SKIP_DIRS  = {
    # deps / build artifacts
    '.git', 'node_modules', 'venv', '.venv', '__pycache__',
    'dist', 'build', '.next', 'vendor', '.tox', '.mypy_cache',
    '.cache', '.parcel-cache', '.turbo', 'coverage', '.nyc_output',
    # macOS app bundles & frameworks
    'Frameworks', 'Resources', 'MacOS', 'PlugIns', 'SharedSupport',
    # electron / packaging
    'app-asar', 'swiftshader', 'locales',
}
SKIP_EXTS  = {
    # images / fonts / media
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff',
    '.woff2', '.ttf', '.eot', '.otf', '.mp4', '.mp3', '.webp',
    # archives & binaries
    '.zip', '.tar', '.gz', '.br', '.bz2',
    '.lock', '.pyc', '.exe', '.dmg', '.pkg',
    '.dll', '.so', '.dylib', '.node',
    # data
    '.db', '.sqlite', '.sqlite3',
    # compiled / map files
    '.map', '.min.js', '.min.css',
    # asar (electron packed archive)
    '.asar',
}
SKIP_FILES = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
              'Pipfile.lock', 'poetry.lock', 'composer.lock'}

MAX_DEPTH  = 10   # don't recurse deeper than this

_ENV_FILE_RE = re.compile(r'^\.env(\..+)?$')

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


# ── Core helpers ───────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _severity(reason: str) -> str:
    r = reason.lower()
    if any(x in r for x in ('private key', 'pgp', 'aws', 'stripe live', 'stripe secret')):
        return 'critical'
    if any(x in r for x in ('github', 'slack', 'google', 'sendgrid', 'mailgun',
                             'npm', 'openai', 'jwt', 'iam')):
        return 'high'
    if 'high-entropy' in r or '.env file' in r:
        return 'high'
    return 'medium'


# ── File scanner ───────────────────────────────────────────────────────────

def scan_content(content: str, filepath: str) -> list[dict]:
    """
    Scan file content for secrets.
    Returns list of dicts: {line, match, reason, severity}
    """
    findings: list[dict] = []
    lines = content.splitlines()

    if _ENV_FILE_RE.match(Path(filepath).name):
        findings.append({
            'line': 0,
            'match': filepath,
            'reason': '.env file should never be committed — add it to .gitignore',
            'severity': 'high',
        })
        return findings

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(('#', '//', '*')):
            continue
        if 're.compile(' in line or 're.Pattern' in line:
            continue

        # 1 — known patterns
        for pattern, label in PATTERNS:
            m = pattern.search(line)
            if m:
                findings.append({
                    'line': lineno,
                    'match': m.group(0)[:60],
                    'reason': label,
                    'severity': _severity(label),
                })
                break

        # 2 — high-entropy assignments
        for assign_re in _ASSIGN_RE:
            for m in assign_re.finditer(line):
                val = m.group(1)
                if _entropy(val) >= 4.5 and len(val) >= 20:
                    if not any(f['line'] == lineno for f in findings):
                        preview = val[:40] + ('…' if len(val) > 40 else '')
                        findings.append({
                            'line': lineno,
                            'match': preview,
                            'reason': f'High-entropy value (entropy={_entropy(val):.1f}) — possible hardcoded secret',
                            'severity': 'high',
                        })
                    break

    return findings


def scan_file(filepath: str) -> list[dict]:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        findings = scan_content(content, filepath)
        for f in findings:
            f['file'] = filepath
        return findings
    except (OSError, PermissionError):
        return []


# ── Directory walker ───────────────────────────────────────────────────────

MAX_FILES = 3000


def collect_files(root: str, max_files: int = MAX_FILES) -> tuple[list[str], bool]:
    """
    Walk directory and return (files, truncated).
    truncated=True means there were more files than max_files.
    Respects MAX_DEPTH and SKIP_DIRS to avoid crawling into binaries/bundles.
    """
    root = os.path.abspath(root)
    root_depth = root.rstrip(os.sep).count(os.sep)
    files = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Depth check — prune dirs that are too deep
        current_depth = dirpath.rstrip(os.sep).count(os.sep) - root_depth
        if current_depth >= MAX_DEPTH:
            dirnames.clear()
            continue

        # Skip unwanted dirs in-place (modifying dirnames prunes the walk)
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.endswith('.app')
        ]

        for fname in filenames:
            if fname in SKIP_FILES:
                continue
            ext = Path(fname).suffix.lower()
            if ext in SKIP_EXTS:
                continue
            # Skip minified files by name pattern
            if fname.endswith('.min.js') or fname.endswith('.min.css'):
                continue
            files.append(os.path.join(dirpath, fname))
            if len(files) >= max_files:
                return files, True

    return files, False


def count_files(root: str) -> int:
    """Quick file count (stops at MAX_FILES + 1 so we can show 3000+)."""
    files, truncated = collect_files(root, MAX_FILES + 1)
    return len(files)


def collect_staged_files(repo_path: str = '.') -> list[str] | None:
    """Return staged file paths, or None if not a git repo."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
            capture_output=True, text=True, check=True, cwd=repo_path,
        )
        return [
            os.path.join(repo_path, f)
            for f in result.stdout.splitlines() if f.strip()
        ]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


# ── Top-level scan ─────────────────────────────────────────────────────────

def scan(path: str, mode: str = 'all') -> dict:
    """
    Run a scan and return a structured result dict.

    mode: 'all'    — scan all files under path
          'staged' — scan only git-staged files
    """
    truncated = False
    if mode == 'staged':
        files = collect_staged_files(path)
        if files is None:
            return {'ok': False, 'error': 'Not a git repository or git not found.'}
        if not files:
            return {'ok': True, 'findings': [], 'scanned': 0, 'mode': 'staged'}
    else:
        p = Path(path)
        if p.is_file():
            files = [str(p)]
        elif p.is_dir():
            files, truncated = collect_files(str(p))
        else:
            return {'ok': False, 'error': f'Path not found: {path}'}

    all_findings: list[dict] = []
    for filepath in files:
        all_findings.extend(scan_file(filepath))

    # Sort by severity then file then line
    all_findings.sort(key=lambda f: (
        SEVERITY_ORDER.get(f['severity'], 9),
        f['file'],
        f['line'],
    ))

    return {
        'ok': True,
        'findings': all_findings,
        'scanned': len(files),
        'truncated': truncated,
        'mode': mode,
        'path': path,
    }


# ── Git hook installer ─────────────────────────────────────────────────────

HOOK_SCRIPT = """\
#!/bin/sh
# Dotward pre-commit hook
# Scans staged files for hardcoded secrets before allowing a commit.
# Installed by: dotward install-hook

if command -v dotward >/dev/null 2>&1; then
    dotward scan
    exit $?
else
    echo "dotward: CLI not found in PATH — skipping secret scan."
    echo "Install from: https://github.com/Anuvrat14/dotward"
    exit 0
fi
"""


def install_hook(repo_path: str) -> dict:
    """Install pre-commit hook into repo_path/.git/hooks/pre-commit."""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            capture_output=True, text=True, check=True, cwd=repo_path,
        )
        git_dir = result.stdout.strip()
        if not os.path.isabs(git_dir):
            git_dir = os.path.join(repo_path, git_dir)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {'ok': False, 'error': 'Not a git repository or git not found.'}

    hooks_dir = Path(git_dir) / 'hooks'
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / 'pre-commit'

    if hook_path.exists():
        existing = hook_path.read_text()
        if 'dotward scan' in existing:
            return {'ok': True, 'status': 'already_installed', 'path': str(hook_path)}
        with open(hook_path, 'a') as f:
            f.write('\n# Dotward secret scan\ndotward scan\n')
        return {'ok': True, 'status': 'appended', 'path': str(hook_path)}

    hook_path.write_text(HOOK_SCRIPT)
    hook_path.chmod(0o755)
    return {'ok': True, 'status': 'installed', 'path': str(hook_path)}
