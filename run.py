"""Entry point for Envault Flask server."""
from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=7331, debug=False)
