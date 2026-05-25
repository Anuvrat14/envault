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
    lines   = [f'# {project.name}', f'# Exported by Dotward', '']

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


# --------------------------------------------------------------------------- #
# Security Overview
# --------------------------------------------------------------------------- #

@projects_bp.route('/security')
@require_unlock
def security_overview():
    from math import log2

    all_vars     = EnvVariable.query.all()
    all_projects = Project.query.order_by(Project.name).all()
    now          = datetime.now(timezone.utc)

    # ── Per-variable expiry helpers ────────────────────────────────────────
    def _exp(v):
        if not v.expires_at: return None
        e = v.expires_at
        return e.replace(tzinfo=timezone.utc) if e.tzinfo is None else e

    # ── Risk counts ────────────────────────────────────────────────────────
    risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0, 'dismissed': 0}
    for v in all_vars:
        rl = v.risk_level or 'none'
        risk_counts[rl] = risk_counts.get(rl, 0) + 1

    # ── Expiry stats ───────────────────────────────────────────────────────
    expired_count   = sum(1 for v in all_vars if _exp(v) and _exp(v) < now)
    expiring_7      = sum(1 for v in all_vars if _exp(v) and now <= _exp(v) <= now + timedelta(days=7))
    expiring_30     = sum(1 for v in all_vars if _exp(v) and now <= _exp(v) <= now + timedelta(days=30))
    expiring_60     = sum(1 for v in all_vars if _exp(v) and now <= _exp(v) <= now + timedelta(days=60))
    expiring_90     = sum(1 for v in all_vars if _exp(v) and now <= _exp(v) <= now + timedelta(days=90))
    no_expiry_count = sum(1 for v in all_vars if not v.expires_at)
    has_expiry      = len(all_vars) - no_expiry_count

    # ── Overall security score ─────────────────────────────────────────────
    def _score(var_list):
        if not var_list: return 100
        weights = {'critical': 28, 'high': 16, 'medium': 7, 'low': 2}
        penalty = 0
        for v in var_list:
            penalty += weights.get(v.risk_level or 'none', 0)
            e = _exp(v)
            if e:
                if e < now:              penalty += 12
                elif (e - now).days <= 7: penalty += 6
        avg = penalty / len(var_list)
        return max(0, min(100, round(100 - avg)))

    overall_score = _score(all_vars)

    # ── Radar dimensions (0–100 each) ──────────────────────────────────────
    total = len(all_vars) or 1

    # 1. Credential Strength — % of vars with no entropy/length issues
    entropy_issues = sum(1 for v in all_vars
                         if v.risk_notes and ('entropy' in v.risk_notes or 'chars' in v.risk_notes))
    credential_strength = round(100 * (1 - entropy_issues / total))

    # 2. Value Hygiene — % without weak/placeholder values
    hygiene_issues = sum(1 for v in all_vars
                         if v.risk_notes and ('weak' in v.risk_notes or 'placeholder' in v.risk_notes
                                              or 'default' in v.risk_notes))
    value_hygiene = round(100 * (1 - hygiene_issues / total))

    # 3. Rotation Coverage — % of vars with expiry set
    rotation_coverage = round(100 * has_expiry / total)

    # 4. No Live Keys — % without cloud key detection
    live_key_issues = sum(1 for v in all_vars
                          if v.risk_notes and ('live' in v.risk_notes.lower()
                                               or 'aws' in v.risk_notes.lower()
                                               or 'github' in v.risk_notes.lower()
                                               or 'stripe' in v.risk_notes.lower()
                                               or 'openai' in v.risk_notes.lower()
                                               or 'slack' in v.risk_notes.lower()
                                               or 'google' in v.risk_notes.lower()))
    no_live_keys = round(100 * (1 - live_key_issues / total))

    # 5. Format Compliance — % of URL vars passing format check
    format_issues = sum(1 for v in all_vars
                        if v.risk_notes and 'url' in v.risk_notes.lower())
    format_compliance = round(100 * (1 - format_issues / total))

    # 6. Expiry Hygiene — % not expired and not expiring soon
    expiry_bad = expired_count + expiring_7
    expiry_hygiene = round(100 * (1 - expiry_bad / total))

    radar_data = [
        credential_strength, value_hygiene, rotation_coverage,
        no_live_keys, format_compliance, expiry_hygiene
    ]

    # ── Per-project scores ─────────────────────────────────────────────────
    project_scores = []
    for p in all_projects:
        vs = [v for v in all_vars if v.project_id == p.id]
        project_scores.append({
            'id':       p.id,
            'name':     p.name,
            'score':    _score(vs),
            'total':    len(vs),
            'critical': sum(1 for v in vs if v.risk_level == 'critical'),
            'high':     sum(1 for v in vs if v.risk_level == 'high'),
            'medium':   sum(1 for v in vs if v.risk_level == 'medium'),
            'color':    p.color,
        })
    project_scores.sort(key=lambda x: x['score'])

    # ── Risk type breakdown ────────────────────────────────────────────────
    type_counts = {
        'Weak/Default': sum(1 for v in all_vars if v.risk_notes and
                           ('weak' in v.risk_notes or 'default' in v.risk_notes)),
        'Low Entropy':  sum(1 for v in all_vars if v.risk_notes and 'entropy' in v.risk_notes),
        'Short Secret': sum(1 for v in all_vars if v.risk_notes and 'chars' in v.risk_notes),
        'Live Key':     sum(1 for v in all_vars if v.risk_notes and
                           any(x in v.risk_notes.lower() for x in ['aws','github','stripe','openai','slack','google','live'])),
        'Placeholder':  sum(1 for v in all_vars if v.risk_notes and 'placeholder' in v.risk_notes),
        'Format':       sum(1 for v in all_vars if v.risk_notes and 'url' in v.risk_notes.lower()),
        'Expired':      expired_count,
    }

    # ── All flagged variables ──────────────────────────────────────────────
    flagged = [v for v in all_vars
               if (v.risk_level and v.risk_level not in ('none', 'dismissed', None))
               or ((_exp(v) and _exp(v) < now))]
    flagged.sort(key=lambda v: (
        {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(v.risk_level or 'none', 4)
    ))

    return render_template(
        'security.html',
        overall_score    = overall_score,
        all_project_list = all_projects,
        total_vars       = len(all_vars),
        risk_counts      = risk_counts,
        expired_count    = expired_count,
        expiring_7       = expiring_7,
        expiring_30      = expiring_30,
        expiring_60      = expiring_60,
        expiring_90      = expiring_90,
        no_expiry_count  = no_expiry_count,
        has_expiry       = has_expiry,
        radar_data       = radar_data,
        project_scores   = project_scores,
        type_counts      = type_counts,
        flagged          = flagged,
        all_projects     = {p.id: p.name for p in all_projects},
    )


# --------------------------------------------------------------------------- #
# Per-project Security Report
# --------------------------------------------------------------------------- #

@projects_bp.route('/projects/<int:project_id>/security')
@require_unlock
def project_security(project_id):
    project  = Project.query.get_or_404(project_id)
    vars_    = project.variables          # already ordered by key
    now      = datetime.now(timezone.utc)

    def _exp(v):
        if not v.expires_at: return None
        e = v.expires_at
        return e.replace(tzinfo=timezone.utc) if e.tzinfo is None else e

    # ── Score ────────────────────────────────────────────────────────────────
    weights = {'critical': 28, 'high': 16, 'medium': 7, 'low': 2}
    penalty = 0
    for v in vars_:
        penalty += weights.get(v.risk_level or 'none', 0)
        e = _exp(v)
        if e:
            if e < now:               penalty += 12
            elif (e - now).days <= 7: penalty += 6
    score = max(0, min(100, round(100 - penalty / len(vars_)))) if vars_ else 100

    # ── Risk counts ──────────────────────────────────────────────────────────
    risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0, 'dismissed': 0}
    for v in vars_:
        rl = v.risk_level or 'none'
        risk_counts[rl] = risk_counts.get(rl, 0) + 1

    total = len(vars_) or 1

    # ── Expiry buckets ────────────────────────────────────────────────────────
    expired_     = [v for v in vars_ if _exp(v) and _exp(v) < now]
    expiring_7_  = [v for v in vars_ if _exp(v) and now <= _exp(v) <= now + timedelta(days=7)]
    expiring_30_ = [v for v in vars_ if _exp(v) and now < _exp(v) <= now + timedelta(days=30)]
    no_expiry_   = [v for v in vars_ if not v.expires_at]
    has_expiry   = len(vars_) - len(no_expiry_)

    # ── Conformance checks breakdown ──────────────────────────────────────────
    checks = {
        'Live Cloud Key':      [v for v in vars_ if v.risk_notes and any(
            x in v.risk_notes.lower() for x in ['aws','github','stripe','openai','slack','google','live','sendgrid','npm','mailgun'])],
        'Weak / Default Value':[v for v in vars_ if v.risk_notes and
            ('weak' in v.risk_notes or 'default' in v.risk_notes)],
        'Placeholder Value':   [v for v in vars_ if v.risk_notes and 'placeholder' in v.risk_notes],
        'Low Entropy':         [v for v in vars_ if v.risk_notes and 'entropy' in v.risk_notes],
        'Short Secret':        [v for v in vars_ if v.risk_notes and 'chars' in v.risk_notes],
        'URL Format':          [v for v in vars_ if v.risk_notes and 'url' in v.risk_notes.lower()],
        'Low Char Diversity':  [v for v in vars_ if v.risk_notes and 'diversity' in v.risk_notes.lower()],
        'Empty Value':         [v for v in vars_ if v.risk_notes and 'empty' in v.risk_notes.lower()],
    }

    # ── Radar (project-scoped) ────────────────────────────────────────────────
    credential_strength = round(100 * (1 - (len(checks['Low Entropy']) + len(checks['Short Secret'])) / total))
    value_hygiene       = round(100 * (1 - (len(checks['Weak / Default Value']) + len(checks['Placeholder Value'])) / total))
    rotation_coverage   = round(100 * has_expiry / total)
    no_live_keys        = round(100 * (1 - len(checks['Live Cloud Key']) / total))
    format_compliance   = round(100 * (1 - len(checks['URL Format']) / total))
    expiry_bad          = len(expired_) + len(expiring_7_)
    expiry_hygiene      = round(100 * (1 - expiry_bad / total))
    radar_data          = [credential_strength, value_hygiene, rotation_coverage,
                           no_live_keys, format_compliance, expiry_hygiene]

    # ── Per-variable detail rows ──────────────────────────────────────────────
    var_rows = []
    for v in vars_:
        e        = _exp(v)
        is_exp   = e and e < now
        days_left= ((e - now).days) if e and not is_exp else None
        issues   = [c for c, vlist in checks.items() if v in vlist]
        var_rows.append({
            'var':       v,
            'is_exp':    is_exp,
            'days_left': days_left,
            'issues':    issues,
            'clean':     not issues and not is_exp,
        })

    # ── Recommendations ───────────────────────────────────────────────────────
    recs = []
    if checks['Live Cloud Key']:
        recs.append({'level':'critical', 'text': f'{len(checks["Live Cloud Key"])} live service key(s) detected — rotate immediately and consider using a secrets manager.'})
    if checks['Weak / Default Value']:
        recs.append({'level':'high', 'text': f'{len(checks["Weak / Default Value"])} variable(s) use known weak or default values — replace with strong random secrets.'})
    if checks['Placeholder Value']:
        recs.append({'level':'high', 'text': f'{len(checks["Placeholder Value"])} placeholder value(s) found — these likely haven\'t been configured yet.'})
    if checks['Low Entropy']:
        recs.append({'level':'high', 'text': f'{len(checks["Low Entropy"])} secret(s) have low entropy — use a cryptographically random generator.'})
    if checks['Short Secret']:
        recs.append({'level':'medium', 'text': f'{len(checks["Short Secret"])} secret(s) are shorter than recommended — minimum 16 chars, ideally 32+.'})
    if len(no_expiry_) > 0:
        recs.append({'level':'medium', 'text': f'{len(no_expiry_)} variable(s) have no rotation reminder set — set expiry on all secrets.'})
    if expired_:
        recs.append({'level':'high', 'text': f'{len(expired_)} variable(s) have expired — rotate them now.'})
    if expiring_7_:
        recs.append({'level':'medium', 'text': f'{len(expiring_7_)} variable(s) expire within 7 days — schedule rotation.'})
    if not recs:
        recs.append({'level':'ok', 'text': 'No issues found. All variables pass conformance checks.'})

    return render_template(
        'project_security.html',
        project          = project,
        score            = score,
        risk_counts      = risk_counts,
        total_vars       = len(vars_),
        has_expiry       = has_expiry,
        expired_         = expired_,
        expiring_7_      = expiring_7_,
        expiring_30_     = expiring_30_,
        no_expiry_       = no_expiry_,
        checks           = {k: len(v) for k, v in checks.items()},
        var_rows         = var_rows,
        radar_data       = radar_data,
        recs             = recs,
        now              = now,
    )
