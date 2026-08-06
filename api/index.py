import os
import sys

# Ensure root directory is in sys.path for relative & absolute imports
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from analysis.app import app

# Export Flask app for Vercel Serverless Function handler
app = app
