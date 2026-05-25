"""
Project and variable routes.
All variable values are encrypted/decrypted in-request using the session key.
"""
import io
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Blueprint, Response, flash, jsonify, redirect,
                   render_template, request, session, url_for)

from crypto import decrypt_value, encrypt_value
from models import EnvVariable, Project, db
from risk_engine import analyze as risk_analyze

projects_bp = Blueprint('projects', __name__)

# Project badge colours to cycle through
_COLOURS = ['#6c757d', '#3498db', '#2ecc71', '#e67e22', '#9b59b6',
            '#e74c3c', '#1abc9c', '#f39c12']


# --------------------------------------------------------------------------- #
# Auth guard
# --------------------------------------------------------------------------- #

def require_unlock(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'enc_key' not in session:
            return redirect(url_for('auth.unlock'))
        return f(*args, **kwargs)
    return decorated


def _key() -> bytes:
    return bytes.fromhex(session['enc_key'])


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #

@projects_bp.route('/dashboard')
@require_unlock
def dashboard():
    projects = Project.query.order_by(Project.updated_at.desc()).all()
    counts   = {p.id: len(p.variables) for p in projects}
    return render_template('dashboard.html', projects=projects, counts=counts)


# --------------------------------------------------------------------------- #
# Create project
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/new', methods=['POST'])
@require_unlock
def create_project():
    name        = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()

    if not name:
        flash('Project name is required.', 'danger')
        return redirect(url_for('projects.dashboard'))

    # Pick a colour based on current count
    colour_index = Project.query.count() % len(_COLOURS)
    project = Project(name=name, description=description or None,
                      color=_COLOURS[colour_index])
    db.session.add(project)
    db.session.commit()
    return redirect(url_for('projects.view_project', project_id=project.id))


# --------------------------------------------------------------------------- #
# View project
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>')
@require_unlock
def view_project(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('project.html', project=project)


# --------------------------------------------------------------------------- #
# Add variable
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>/variables', methods=['POST'])
@require_unlock
def add_variable(project_id):
    project = Project.query.get_or_404(project_id)
    key     = request.form.get('key', '').strip().upper()
    value   = request.form.get('value', '')
    notes   = request.form.get('notes', '').strip()

    if not key:
        flash('Variable key is required.', 'danger')
        return redirect(url_for('projects.view_project', project_id=project_id))

    if not re.match(r'^[A-Z_][A-Z0-9_]*$', key):
        flash('Key must contain only uppercase letters, digits, and underscores.', 'danger')
        return redirect(url_for('projects.view_project', project_id=project_id))

    existing = EnvVariable.query.filter_by(project_id=project_id, key=key).first()
    if existing:
        flash(f'{key} already exists in this project. Delete it first to overwrite.', 'warning')
        return redirect(url_for('projects.view_project', project_id=project_id))

    encrypted             = encrypt_value(value, _key())
    risk_level, risk_note = risk_analyze(key, value)
    var = EnvVariable(project_id=project_id, key=key,
                      encrypted_value=encrypted, notes=notes or None,
                      risk_level=risk_level or None,
                      risk_notes=risk_note or None)
    db.session.add(var)

    # Bump project updated_at
    project.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return redirect(url_for('projects.view_project', project_id=project_id))


# --------------------------------------------------------------------------- #
# Delete variable
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>/variables/<int:var_id>/delete',
                   methods=['POST'])
@require_unlock
def delete_variable(project_id, var_id):
    var = EnvVariable.query.filter_by(id=var_id, project_id=project_id).first_or_404()
    db.session.delete(var)
    db.session.commit()
    return redirect(url_for('projects.view_project', project_id=project_id))


# --------------------------------------------------------------------------- #
# Copy value (AJAX — returns plaintext for clipboard)
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>/variables/<int:var_id>/copy',
                   methods=['POST'])
@require_unlock
def copy_variable(project_id, var_id):
    var = EnvVariable.query.filter_by(id=var_id, project_id=project_id).first_or_404()
    try:
        plaintext = decrypt_value(var.encrypted_value, _key())
        return jsonify({'value': plaintext})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


# --------------------------------------------------------------------------- #
# Import .env file
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>/import', methods=['POST'])
@require_unlock
def import_env(project_id):
    project = Project.query.get_or_404(project_id)
    file    = request.files.get('env_file')

    if not file or not file.filename:
        flash('No file selected.', 'danger')
        return redirect(url_for('projects.view_project', project_id=project_id))

    content = file.read().decode('utf-8', errors='replace')
    added   = 0
    skipped = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            continue

        raw_key, _, raw_value = line.partition('=')
        k = raw_key.strip().upper()
        v = raw_value.strip().strip('"').strip("'")

        if not re.match(r'^[A-Z_][A-Z0-9_]*$', k):
            skipped.append(k)
            continue

        rl, rn = risk_analyze(k, v)
        existing = EnvVariable.query.filter_by(project_id=project_id, key=k).first()
        if existing:
            existing.encrypted_value = encrypt_value(v, _key())
            existing.risk_level      = rl or None
            existing.risk_notes      = rn or None
            existing.updated_at      = datetime.now(timezone.utc)
        else:
            var = EnvVariable(project_id=project_id, key=k,
                              encrypted_value=encrypt_value(v, _key()),
                              risk_level=rl or None, risk_notes=rn or None)
            db.session.add(var)
        added += 1

    project.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    msg = f'Imported {added} variable{"s" if added != 1 else ""}.'
    if skipped:
        msg += f' Skipped {len(skipped)} invalid key(s): {", ".join(skipped[:5])}'
    flash(msg, 'success' if added else 'warning')
    return redirect(url_for('projects.view_project', project_id=project_id))


# --------------------------------------------------------------------------- #
# Export .env file
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>/export')
@require_unlock
def export_env(project_id):
    project = Project.query.get_or_404(project_id)
    lines   = [f'# {project.name}', f'# Exported by Envault', '']

    for var in sorted(project.variables, key=lambda v: v.key):
        try:
            plaintext = decrypt_value(var.encrypted_value, _key())
        except ValueError:
            plaintext = ''
        if var.notes:
            lines.append(f'# {var.notes}')
        lines.append(f'{var.key}={plaintext}')

    content  = '\n'.join(lines) + '\n'
    filename = f'{project.name.lower().replace(" ", "_")}.env'
    return Response(
        content,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


# --------------------------------------------------------------------------- #
# Delete project
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>/delete', methods=['POST'])
@require_unlock
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    flash(f'Project "{project.name}" deleted.', 'success')
    return redirect(url_for('projects.dashboard'))


# --------------------------------------------------------------------------- #
# Edit project name/description
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>/edit', methods=['POST'])
@require_unlock
def edit_project(project_id):
    project     = Project.query.get_or_404(project_id)
    name        = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    if name:
        project.name        = name
        project.description = description or None
        project.updated_at  = datetime.now(timezone.utc)
        db.session.commit()
    return redirect(url_for('projects.view_project', project_id=project_id))


# --------------------------------------------------------------------------- #
# Set expiry on a variable
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>/variables/<int:var_id>/expiry',
                   methods=['POST'])
@require_unlock
def set_expiry(project_id, var_id):
    var           = EnvVariable.query.filter_by(id=var_id, project_id=project_id).first_or_404()
    rotation_days = request.form.get('rotation_days', '').strip()
    expires_at    = request.form.get('expires_at', '').strip()

    if rotation_days:
        try:
            days = int(rotation_days)
            if days < 1:
                raise ValueError
            var.rotation_days = days
            var.expires_at    = datetime.now(timezone.utc) + timedelta(days=days)
            var.last_rotated  = datetime.now(timezone.utc)
        except ValueError:
            flash('Rotation days must be a positive integer.', 'danger')
            return redirect(url_for('projects.view_project', project_id=project_id))
    elif expires_at:
        try:
            var.expires_at = datetime.fromisoformat(expires_at).replace(tzinfo=timezone.utc)
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('projects.view_project', project_id=project_id))
    else:
        var.expires_at    = None
        var.rotation_days = None

    db.session.commit()
    flash(f'Expiry set for {var.key}.', 'success')
    return redirect(url_for('projects.view_project', project_id=project_id))


# --------------------------------------------------------------------------- #
# Mark variable as rotated (resets expiry clock)
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>/variables/<int:var_id>/rotated',
                   methods=['POST'])
@require_unlock
def mark_rotated(project_id, var_id):
    var = EnvVariable.query.filter_by(id=var_id, project_id=project_id).first_or_404()
    var.last_rotated = datetime.now(timezone.utc)
    if var.rotation_days:
        var.expires_at = datetime.now(timezone.utc) + timedelta(days=var.rotation_days)
    db.session.commit()
    return jsonify({'status': 'ok', 'next_expiry': var.expires_at.isoformat() if var.expires_at else None})


# --------------------------------------------------------------------------- #
# Dismiss risk flag
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>/variables/<int:var_id>/dismiss-risk',
                   methods=['POST'])
@require_unlock
def dismiss_risk(project_id, var_id):
    var            = EnvVariable.query.filter_by(id=var_id, project_id=project_id).first_or_404()
    var.risk_level = 'dismissed'
    var.risk_notes = None
    db.session.commit()
    return jsonify({'status': 'ok'})


# --------------------------------------------------------------------------- #
# Notification check — polled by Electron every 60s
# --------------------------------------------------------------------------- #

@projects_bp.route('/api/notifications/check')
@require_unlock
def notification_check():
    now        = datetime.now(timezone.utc)
    warn_soon  = now + timedelta(days=7)
    notifs     = []

    vars_with_expiry = EnvVariable.query.filter(
        EnvVariable.expires_at.isnot(None)
    ).all()

    for var in vars_with_expiry:
        exp = var.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= now:
            notifs.append({
                'type':    'expired',
                'key':     var.key,
                'project': var.project.name,
                'message': f'{var.key} in "{var.project.name}" has expired — rotate now',
            })
        elif exp <= warn_soon:
            days_left = (exp - now).days
            notifs.append({
                'type':    'expiring',
                'key':     var.key,
                'project': var.project.name,
                'message': f'{var.key} in "{var.project.name}" expires in {days_left} day{"s" if days_left != 1 else ""}',
            })

    # Critical risk variables
    critical_vars = EnvVariable.query.filter_by(risk_level='critical').all()
    for var in critical_vars:
        notifs.append({
            'type':    'risk',
            'key':     var.key,
            'project': var.project.name,
            'message': f'Critical risk: {var.key} in "{var.project.name}" — {var.risk_notes}',
        })

    return jsonify({'notifications': notifs})
