import os
import sys

# Set Vercel serverless environment flag
os.environ["VERCEL"] = "1"

# Add project root to sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from analysis.app import app

# Export Flask app for Vercel WSGI runner
app = app
