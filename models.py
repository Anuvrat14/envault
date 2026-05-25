"""
Database models for Dotward.
SQLite via SQLAlchemy — fully local, no external DB.
"""
import enum
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class AppConfig(db.Model):
    """Single-row table storing master password hash + salt."""
    __tablename__ = 'app_config'

    id             = db.Column(db.Integer, primary_key=True)
    password_hash  = db.Column(db.String(256), nullable=False)
    salt           = db.Column(db.LargeBinary(32), nullable=False)   # encryption salt
    backup_codes   = db.Column(db.Text, nullable=True)               # JSON array of wrapped code objects
    cli_token      = db.Column(db.String(128), nullable=True)        # token for CLI API access
    created_at     = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at     = db.Column(db.DateTime, onupdate=lambda: datetime.now(timezone.utc))


class Project(db.Model):
    """A named collection of env variables — e.g. 'MyApp Production'."""
    __tablename__ = 'projects'

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300), nullable=True)
    color       = db.Column(db.String(7), default='#6c757d')   # hex color for UI badge
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at  = db.Column(db.DateTime,
                            default=lambda: datetime.now(timezone.utc),
                            onupdate=lambda: datetime.now(timezone.utc))

    variables = db.relationship('EnvVariable', backref='project',
                                cascade='all, delete-orphan',
                                order_by='EnvVariable.key')

    def __repr__(self):
        return f'<Project {self.name}>'


class EnvVariable(db.Model):
    """A single key=value pair, value encrypted at rest."""
    __tablename__ = 'env_variables'

    id              = db.Column(db.Integer, primary_key=True)
    project_id      = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    key             = db.Column(db.String(200), nullable=False)
    encrypted_value = db.Column(db.Text, nullable=False)   # AES-256-GCM blob
    notes           = db.Column(db.String(500), nullable=True)
    # Expiry / rotation
    expires_at      = db.Column(db.DateTime, nullable=True)
    rotation_days   = db.Column(db.Integer, nullable=True)   # e.g. 90
    last_rotated    = db.Column(db.DateTime, nullable=True)
    # Risk analysis
    risk_level      = db.Column(db.String(10), nullable=True)  # none/low/medium/high/critical
    risk_notes      = db.Column(db.Text, nullable=True)
    created_at      = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at      = db.Column(db.DateTime,
                                default=lambda: datetime.now(timezone.utc),
                                onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('project_id', 'key', name='uq_project_key'),
    )

    def __repr__(self):
        return f'<EnvVariable {self.key}>'
