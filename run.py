"""
Entry point for Dotward Flask server.
When packaged by PyInstaller, sys._MEIPASS is the temp extraction dir.
We add it to the path so Flask can find templates/static.
"""
import os
import sys

# ── PyInstaller path fix ───────────────────────────────────────────────────
if getattr(sys, 'frozen', False):
    # Running as a PyInstaller bundle
    base_dir = sys._MEIPASS
    os.chdir(base_dir)
    sys.path.insert(0, base_dir)
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

# ── Create and run app ─────────────────────────────────────────────────────
from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('DOTWARD_PORT', 7331))

    if getattr(sys, 'frozen', False):
        # Production: use waitress
        from waitress import serve
        serve(app, host='127.0.0.1', port=port, threads=4)
    else:
        # Development
        app.run(host='127.0.0.1', port=port, debug=False)
