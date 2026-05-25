"""
Envault — Flask application factory.
"""
import os

from flask import Flask
from flask_wtf.csrf import CSRFProtect

from models import db

csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)

    # Config
    data_dir = os.path.join(os.path.expanduser('~'), '.envault')
    os.makedirs(data_dir, exist_ok=True)

    app.config.update(
        SECRET_KEY=_get_or_create_secret(data_dir),
        SQLALCHEMY_DATABASE_URI=f'sqlite:///{os.path.join(data_dir, "envault.db")}',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=3600,
        WTF_CSRF_TIME_LIMIT=None,
    )

    # Extensions
    db.init_app(app)
    csrf.init_app(app)

    # Blueprints
    from routes.auth     import auth_bp
    from routes.projects import projects_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(projects_bp)

    # Create tables
    with app.app_context():
        db.create_all()

    return app


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
