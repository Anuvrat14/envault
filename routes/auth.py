"""
Auth routes — setup (first run), unlock, lock, reset.
The derived encryption key is stored in the Flask session (server-side memory only).
"""
from flask import (Blueprint, redirect, render_template, request,
                   session, url_for, flash)

from crypto import (derive_key, generate_salt, hash_password,
                    generate_backup_codes, wrap_key_with_code, unwrap_key_with_code)
from models import db, AppConfig, Project, EnvVariable
import cli_state

auth_bp = Blueprint('auth', __name__)


def is_setup_done() -> bool:
    return AppConfig.query.first() is not None


def is_unlocked() -> bool:
    return 'enc_key' in session


# --------------------------------------------------------------------------- #
# Setup — first run only
# --------------------------------------------------------------------------- #

@auth_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    if is_setup_done():
        return redirect(url_for('auth.unlock'))

    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm', '')

        if len(password) < 8:
            error = 'Master password must be at least 8 characters.'
        elif password != confirm:
            error = 'Passwords do not match.'
        else:
            salt         = generate_salt()
            password_hash = hash_password(password, salt)
            enc_key      = derive_key(password, salt)

            config = AppConfig(password_hash=password_hash, salt=salt)
            db.session.add(config)
            db.session.commit()

            # Unlock immediately after setup
            session['enc_key'] = enc_key.hex()
            session.permanent = True
            cli_state.set_key(config.cli_token or '', enc_key.hex())
            return redirect(url_for('projects.dashboard'))

    return render_template('setup.html', error=error)


# --------------------------------------------------------------------------- #
# Unlock
# --------------------------------------------------------------------------- #

@auth_bp.route('/', methods=['GET', 'POST'])
@auth_bp.route('/unlock', methods=['GET', 'POST'])
def unlock():
    if not is_setup_done():
        return redirect(url_for('auth.setup'))

    if is_unlocked():
        return redirect(url_for('projects.dashboard'))

    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        config   = AppConfig.query.first()

        expected = hash_password(password, config.salt)
        if expected == config.password_hash:
            enc_key = derive_key(password, config.salt)
            session['enc_key'] = enc_key.hex()
            session.permanent  = True
            cli_state.set_key(config.cli_token or '', enc_key.hex())
            return redirect(url_for('projects.dashboard'))
        else:
            error = 'Incorrect master password.'

    return render_template('unlock.html', error=error)


# --------------------------------------------------------------------------- #
# Lock
# --------------------------------------------------------------------------- #

@auth_bp.route('/lock')
def lock():
    session.clear()
    cli_state.clear()
    return redirect(url_for('auth.unlock'))


# --------------------------------------------------------------------------- #
# Reset vault — wipes ALL data, returns to setup
# --------------------------------------------------------------------------- #

@auth_bp.route('/reset', methods=['GET', 'POST'])
def reset():
    """
    GET  — show confirmation page
    POST — confirm phrase matched, wipe everything, redirect to setup
    """
    CONFIRM_PHRASE = 'reset my vault'
    error = None

    if request.method == 'POST':
        typed = request.form.get('confirm_text', '').strip().lower()
        if typed != CONFIRM_PHRASE:
            error = f'Type exactly: {CONFIRM_PHRASE}'
        else:
            # Wipe all encrypted data and config
            session.clear()
            EnvVariable.query.delete()
            Project.query.delete()
            AppConfig.query.delete()
            db.session.commit()
            flash('Vault has been reset. Set a new master password to continue.', 'warning')
            return redirect(url_for('auth.setup'))

    return render_template('reset.html', error=error, phrase='reset my vault')


# --------------------------------------------------------------------------- #
# Change master password (must be unlocked)
# --------------------------------------------------------------------------- #

@auth_bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'enc_key' not in session:
        return redirect(url_for('auth.unlock'))

    error   = None
    success = False

    via_backup = session.get('force_pw_change', False)

    if request.method == 'POST':
        current  = request.form.get('current_password', '')
        new_pw   = request.form.get('new_password', '')
        confirm  = request.form.get('confirm_password', '')
        config   = AppConfig.query.first()

        # Skip current password check if user recovered via backup code
        if not via_backup and hash_password(current, config.salt) != config.password_hash:
            error = 'Current password is incorrect.'
        elif len(new_pw) < 8:
            error = 'New password must be at least 8 characters.'
        elif new_pw != confirm:
            error = 'New passwords do not match.'
        else:
            from crypto import decrypt_value, encrypt_value
            old_key = bytes.fromhex(session['enc_key'])

            # Re-encrypt every variable with the new key
            new_salt = generate_salt()
            new_key  = derive_key(new_pw, new_salt)
            for var in EnvVariable.query.all():
                try:
                    plaintext = decrypt_value(var.encrypted_value, old_key)
                    var.encrypted_value = encrypt_value(plaintext, new_key)
                except Exception:
                    pass  # corrupted var — leave as-is

            config.salt          = new_salt
            config.password_hash = hash_password(new_pw, new_salt)
            session['enc_key']   = new_key.hex()
            session.pop('force_pw_change', None)
            db.session.commit()
            # Refresh CLI state with the new key
            cli_state.clear()
            cli_state.set_key(config.cli_token or '', new_key.hex())
            success = True

    return render_template('change_password.html', error=error, success=success,
                           via_backup=via_backup)


# --------------------------------------------------------------------------- #
# Settings page
# --------------------------------------------------------------------------- #

@auth_bp.route('/settings')
def settings():
    if 'enc_key' not in session:
        return redirect(url_for('auth.unlock'))
    config = AppConfig.query.first()
    import json
    codes_data = json.loads(config.backup_codes) if config.backup_codes else []
    active_count = sum(1 for c in codes_data if not c.get('used'))
    # Mask the token for display: show first 8 and last 4 chars
    token = config.cli_token or ''
    token_masked = (token[:8] + '••••••••••••' + token[-4:]) if len(token) > 12 else ('••••' if token else '')
    return render_template('settings.html', active_count=active_count,
                           has_codes=bool(codes_data),
                           has_cli_token=bool(token),
                           cli_token_masked=token_masked,
                           cli_token=token)


# --------------------------------------------------------------------------- #
# CLI token management
# --------------------------------------------------------------------------- #

@auth_bp.route('/settings/cli-token/generate', methods=['POST'])
def generate_cli_token():
    if 'enc_key' not in session:
        return redirect(url_for('auth.unlock'))
    import secrets
    config = AppConfig.query.first()
    token  = 'ev_' + secrets.token_urlsafe(32)
    config.cli_token = token
    db.session.commit()
    # Update in-memory state immediately
    cli_state.set_key(token, session['enc_key'])
    flash('New CLI token generated. Download it from Settings.', 'success')
    return redirect(url_for('auth.settings'))


@auth_bp.route('/settings/cli-token/download')
def download_cli_token():
    if 'enc_key' not in session:
        return redirect(url_for('auth.unlock'))
    from flask import Response
    config = AppConfig.query.first()
    if not config or not config.cli_token:
        flash('Generate a CLI token first.', 'warning')
        return redirect(url_for('auth.settings'))
    return Response(
        config.cli_token + '\n',
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename="dotward_cli_token"'}
    )


@auth_bp.route('/cli/download')
def download_cli_script():
    """Serve the dotward CLI Python script as a download."""
    import os
    from flask import send_file
    script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dotward_cli.py')
    return send_file(script_path, as_attachment=True,
                     download_name='dotward', mimetype='text/x-python')


@auth_bp.route('/cli-docs')
def cli_docs():
    if 'enc_key' not in session:
        return redirect(url_for('auth.unlock'))
    return render_template('cli_docs.html')


# --------------------------------------------------------------------------- #
# Generate backup codes (must be unlocked — wraps the live enc key)
# --------------------------------------------------------------------------- #

@auth_bp.route('/settings/backup-codes/generate', methods=['POST'])
def generate_codes():
    if 'enc_key' not in session:
        return redirect(url_for('auth.unlock'))

    import json
    enc_key = bytes.fromhex(session['enc_key'])
    codes   = generate_backup_codes(8)

    codes_data = []
    for code in codes:
        wrapped = wrap_key_with_code(enc_key, code)
        wrapped['used'] = False
        codes_data.append(wrapped)

    config = AppConfig.query.first()
    config.backup_codes = json.dumps(codes_data)
    db.session.commit()

    # Store plaintext codes in session just long enough to download
    session['pending_codes'] = codes
    return redirect(url_for('auth.download_codes'))


# --------------------------------------------------------------------------- #
# Download backup codes as a text file
# --------------------------------------------------------------------------- #

@auth_bp.route('/settings/backup-codes/download')
def download_codes():
    if 'enc_key' not in session:
        return redirect(url_for('auth.unlock'))

    codes = session.pop('pending_codes', None)
    if not codes:
        flash('Generate new codes first.', 'warning')
        return redirect(url_for('auth.settings'))

    from flask import Response
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    lines = [
        'DOTWARD BACKUP CODES',
        '====================',
        f'Generated: {timestamp}',
        '',
        'Each code can be used ONCE to recover access to your vault.',
        'Store this file somewhere safe and offline.',
        '',
    ]
    for i, code in enumerate(codes, 1):
        lines.append(f'  {i}.  {code}')
    lines += [
        '',
        'After using a code, generate a new set immediately.',
        'These codes will not be shown again.',
    ]

    return Response(
        '\n'.join(lines) + '\n',
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename="dotward-backup-codes.txt"'}
    )


# --------------------------------------------------------------------------- #
# Unlock with backup code
# --------------------------------------------------------------------------- #

@auth_bp.route('/unlock-with-code', methods=['GET', 'POST'])
def unlock_with_code():
    if not is_setup_done():
        return redirect(url_for('auth.setup'))

    error = None
    if request.method == 'POST':
        import json
        entered = request.form.get('code', '').strip().upper().replace(' ', '').replace('-', '')
        config  = AppConfig.query.first()

        if not config.backup_codes:
            error = 'No backup codes have been generated for this vault.'
        else:
            codes_data = json.loads(config.backup_codes)
            recovered  = False
            for i, entry in enumerate(codes_data):
                if entry.get('used'):
                    continue
                try:
                    enc_key = unwrap_key_with_code(entry, entered)
                    # Valid code — mark as used
                    codes_data[i]['used'] = True
                    config.backup_codes   = json.dumps(codes_data)
                    db.session.commit()
                    session['enc_key']    = enc_key.hex()
                    session.permanent     = True
                    session['force_pw_change'] = True
                    cli_state.set_key(config.cli_token or '', enc_key.hex())
                    flash('Backup code accepted. Please set a new master password now.', 'warning')
                    return redirect(url_for('auth.change_password'))
                except ValueError:
                    continue
            if not recovered:
                error = 'Invalid or already-used backup code.'

    return render_template('unlock_with_code.html', error=error)
