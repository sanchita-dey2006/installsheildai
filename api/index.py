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
