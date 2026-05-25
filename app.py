"""
Vaultic — Flask application factory.
"""
import os

from flask import Flask
from flask_wtf.csrf import CSRFProtect

from models import db

csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)

    # Config
    data_dir = os.path.join(os.path.expanduser('~'), '.vaultic')
    os.makedirs(data_dir, exist_ok=True)

    app.config.update(
        SECRET_KEY=_get_or_create_secret(data_dir),
        SQLALCHEMY_DATABASE_URI=f'sqlite:///{os.path.join(data_dir, "vaultic.db")}',
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
    from datetime import datetime, timezone
    app.jinja_env.globals['now_utc'] = lambda: datetime.now(timezone.utc)
    app.jinja_env.globals['app_version'] = _get_version()

    # Blueprints
    from routes.auth     import auth_bp
    from routes.projects import projects_bp
    from routes.api      import api_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(projects_bp)
    app.register_blueprint(api_bp)
    csrf.exempt(api_bp)   # API uses token auth, not CSRF cookies

    # Create tables + migrate existing DBs
    with app.app_context():
        db.create_all()
        _migrate_db(app)

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
    ]
    with db.engine.connect() as conn:
        for table, column, col_type in new_columns:
            try:
                conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {col_type}'))
                conn.commit()
            except Exception:
                pass  # Column already exists


def _get_version() -> str:
    """Read version from package.json, fallback to hardcoded string."""
    import json
    try:
        pkg = os.path.join(os.path.dirname(__file__), 'package.json')
        with open(pkg) as f:
            return json.load(f).get('version', '1.1.0')
    except Exception:
        return '1.1.0'


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
