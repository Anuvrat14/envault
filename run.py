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

# ── MCP subcommand — must start before Flask/watcher ──────────────────────
# When the AI tool runs `dotward-server mcp`, intercept here and go straight
# to the MCP stdio server. Do NOT start Flask or the watcher thread.
if len(sys.argv) > 1 and sys.argv[1] == 'mcp':
    try:
        import mcp_server
        mcp_server.run()
    except ImportError:
        import importlib.util
        spec_path = os.path.join(base_dir, 'mcp_server.py')
        if not os.path.exists(spec_path):
            sys.stderr.write('mcp_server.py not found\n')
            sys.exit(1)
        spec = importlib.util.spec_from_file_location('mcp_server', spec_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.run()
    sys.exit(0)

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
