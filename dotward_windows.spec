# -*- mode: python ; coding: utf-8 -*-
# Dotward Windows PyInstaller Spec

import os
REPO_ROOT = os.path.abspath(SPECPATH)

from PyInstaller.utils.hooks import collect_all

waitress_datas, waitress_binaries, waitress_hiddenimports = collect_all('waitress')

datas = [
    (os.path.join(REPO_ROOT, 'templates'),      'templates'),
    (os.path.join(REPO_ROOT, 'static'),         'static'),
    (os.path.join(REPO_ROOT, 'routes'),         'routes'),
    (os.path.join(REPO_ROOT, 'app.py'),         '.'),
    (os.path.join(REPO_ROOT, 'models.py'),      '.'),
    (os.path.join(REPO_ROOT, 'crypto.py'),      '.'),
    (os.path.join(REPO_ROOT, 'risk_engine.py'), '.'),
    (os.path.join(REPO_ROOT, 'cli_state.py'),   '.'),
    (os.path.join(REPO_ROOT, 'scan_engine.py'), '.'),
    (os.path.join(REPO_ROOT, 'run.py'),         '.'),
] + waitress_datas

hiddenimports = [
    'flask', 'flask.app', 'flask.templating', 'flask.json',
    'flask_sqlalchemy', 'flask_wtf', 'flask_wtf.csrf',
    'werkzeug', 'werkzeug.serving', 'werkzeug.security',
    'jinja2', 'jinja2.loaders',
    'click', 'itsdangerous', 'markupsafe',
    'sqlalchemy', 'sqlalchemy.ext', 'sqlalchemy.ext.declarative',
    'sqlalchemy.orm', 'sqlalchemy.dialects.sqlite',
    'cryptography', 'cryptography.fernet',
    'cryptography.hazmat', 'cryptography.hazmat.primitives',
    'cryptography.hazmat.primitives.hashes',
    'cryptography.hazmat.primitives.kdf',
    'cryptography.hazmat.primitives.kdf.pbkdf2',
    'cryptography.hazmat.primitives.ciphers',
    'cryptography.hazmat.primitives.ciphers.aead',
    'cryptography.hazmat.backends',
    'cryptography.hazmat.backends.openssl',
    'waitress', 'waitress.server',
    'routes.auth', 'routes.projects', 'routes.api', 'routes.scan',
    'risk_engine', 'cli_state', 'scan_engine',
    'hashlib', 'hmac', 'base64', 'secrets', 'uuid',
    'ssl', 'socket', 'threading',
    'logging', 'logging.handlers',
    'json', 'os', 'sys', 'io', 'pathlib',
] + waitress_hiddenimports

a = Analysis(
    [os.path.join(REPO_ROOT, 'run.py')],
    pathex=[REPO_ROOT],
    binaries=waitress_binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib', 'pandas', 'numpy', 'scipy',
        'tkinter', 'turtle', 'test', 'unittest',
        'boto3', 'botocore', 'psycopg2', 'redis',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='dotward-server',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(REPO_ROOT, 'static', 'icon.ico'),
)
