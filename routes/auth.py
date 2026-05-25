"""
Auth routes — setup (first run), unlock, lock.
The derived encryption key is stored in the Flask session (server-side memory only).
"""
from flask import (Blueprint, redirect, render_template, request,
                   session, url_for, flash)

from crypto import derive_key, generate_salt, hash_password
from models import db, AppConfig

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
    return redirect(url_for('auth.unlock'))
