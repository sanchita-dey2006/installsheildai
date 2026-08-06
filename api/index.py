import os
import sys

# Flag environment as Vercel serverless
os.environ["VERCEL"] = "1"

# Resolve absolute paths for Vercel lambda container
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)

for path in [ROOT_DIR, CURRENT_DIR]:
    if path and path not in sys.path:
        sys.path.insert(0, path)

try:
    from analysis.app import app
except Exception as err:
    import traceback
    from flask import Flask, jsonify

    app = Flask(__name__)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def catch_all_fallback(path):
        return jsonify({
            "status": "error",
            "message": "Vercel Serverless Import Diagnostic",
            "error_details": str(err),
            "traceback": traceback.format_exc(),
            "root_dir": ROOT_DIR,
            "sys_path": sys.path
        }), 500


class VercelPathFixMiddleware:
    """WSGI Middleware to normalize Vercel serverless rewritten request paths."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path_info = environ.get("PATH_INFO", "")
        if path_info.startswith("/api/index"):
            new_path = path_info[len("/api/index"):]
            if not new_path or not new_path.startswith("/"):
                new_path = "/" + new_path
            environ["PATH_INFO"] = new_path
        return self.wsgi_app(environ, start_response)


# Wrap Flask WSGI app with VercelPathFixMiddleware
app.wsgi_app = VercelPathFixMiddleware(app.wsgi_app)

# Explicit top-level WSGI assignments for Vercel AST parser
app = app
application = app
handler = app
