"""
Dotward — Flask application factory.
"""
import os

from flask import Flask
from flask_wtf.csrf import CSRFProtect

from models import db

csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)

    # Config
    data_dir = os.path.join(os.path.expanduser('~'), '.dotward')
    os.makedirs(data_dir, exist_ok=True)

    app.config.update(
        SECRET_KEY=_get_or_create_secret(data_dir),
        SQLALCHEMY_DATABASE_URI=f'sqlite:///{os.path.join(data_dir, "dotward.db")}',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=3600,
        WTF_CSRF_TIME_LIMIT=None,
    )

    # Extensions
    db.init_app(app)
    csrf.init_app(app)

    # Jinja globals
    from datetime import datetime
    app.jinja_env.globals['now_utc'] = lambda: datetime.utcnow()
    app.jinja_env.globals['app_version'] = _get_version()

    # Restore cli_state from session after process restart
    # (Flask session is cookie-based and survives restarts, but in-memory
    #  _internal_key is lost — re-sync it on the first request that has a session)
    @app.before_request
    def _sync_cli_state():
        import cli_state
        from flask import session
        if session.get('enc_key') and not cli_state.is_unlocked():
            from models import AppConfig
            config = AppConfig.query.first()
            if config:
                cli_state.set_key(config.cli_token or '', session['enc_key'])

    # Blueprints
    from routes.auth     import auth_bp
    from routes.projects import projects_bp
    from routes.api      import api_bp
    from routes.scan     import scan_bp
    from routes.watcher  import watcher_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(projects_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(watcher_bp)
    csrf.exempt(api_bp)      # API uses token auth, not CSRF cookies
    csrf.exempt(watcher_bp)  # Watcher API uses session auth

    # Create tables + migrate existing DBs
    with app.app_context():
        db.create_all()
        _migrate_db(app)

    # Start AI config file watcher in background
    import watcher_engine
    watcher_engine.start(app)

    return app


def _migrate_db(app):
    """Add new columns to existing databases that predate them."""
    from sqlalchemy import text
    new_columns = [
        ('env_variables', 'expires_at',    'DATETIME'),
        ('env_variables', 'rotation_days', 'INTEGER'),
        ('env_variables', 'last_rotated',  'DATETIME'),
        ('env_variables', 'risk_level',    'VARCHAR(10)'),
        ('env_variables', 'risk_notes',    'TEXT'),
        ('app_config',    'backup_codes',  'TEXT'),
        ('app_config',    'cli_token',     'VARCHAR(128)'),
        ('projects',      'mcp_enabled',   'BOOLEAN DEFAULT 1'),
    ]
    with db.engine.connect() as conn:
        for table, column, col_type in new_columns:
            try:
                conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {col_type}'))
                conn.commit()
            except Exception:
                pass  # Column already exists


def _get_version() -> str:
    """Read version from app.asar (always reflects installed Electron version),
    falling back to _version.py baked in at build time."""
    import sys as _sys, re, json

    # When frozen, sys.executable = .../Contents/Resources/dotward-server
    # app.asar lives in the same Resources folder — always reflects the
    # current Electron installer version even after delta auto-updates.
    if getattr(_sys, 'frozen', False):
        try:
            resources_dir = os.path.dirname(_sys.executable)
            asar_path = os.path.join(resources_dir, 'app.asar')
            if os.path.exists(asar_path):
                with open(asar_path, 'rb') as f:
                    data = f.read(65536)
                m = re.search(rb'"version"\s*:\s*"([^"]+)"', data)
                if m:
                    return m.group(1).decode()
        except Exception:
            pass

    # Dev / fallback: _version.py written by release.sh before PyInstaller
    try:
        from _version import __version__
        return __version__
    except ImportError:
        pass

    try:
        pkg = os.path.join(os.path.dirname(__file__), 'package.json')
        with open(pkg) as f:
            return json.load(f).get('version', '1.0.0')
    except Exception:
        pass

    return '1.0.0'


def _get_or_create_secret(data_dir: str) -> str:
    """Persist a random Flask secret key across restarts."""
    path = os.path.join(data_dir, '.flask_secret')
    if os.path.exists(path):
        with open(path, 'r') as f:
            return f.read().strip()
    secret = os.urandom(32).hex()
    with open(path, 'w') as f:
        f.write(secret)
    return secret
