"""
Project and variable routes.
All variable values are encrypted/decrypted in-request using the session key.
"""
import io
import re
from datetime import datetime, timezone
from functools import wraps

from flask import (Blueprint, Response, flash, jsonify, redirect,
                   render_template, request, session, url_for)

from crypto import decrypt_value, encrypt_value
from models import EnvVariable, Project, db

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

    encrypted = encrypt_value(value, _key())
    var = EnvVariable(project_id=project_id, key=key,
                      encrypted_value=encrypted, notes=notes or None)
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

        existing = EnvVariable.query.filter_by(project_id=project_id, key=k).first()
        if existing:
            # Overwrite value on import
            existing.encrypted_value = encrypt_value(v, _key())
            existing.updated_at = datetime.now(timezone.utc)
        else:
            var = EnvVariable(project_id=project_id, key=k,
                              encrypted_value=encrypt_value(v, _key()))
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
