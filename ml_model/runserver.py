#!/usr/bin/env python
"""
ASGI server for running Django with WebSocket support.
This script uses Daphne to serve both HTTP and WebSocket requests.
"""

import os
import sys
import django
from django.core.asgi import get_asgi_application

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ml_model.settings')
django.setup()

# Import the ASGI application
from ml_model.asgi import application

if __name__ == "__main__":
    import subprocess
    import sys
    
    # Use subprocess to run daphne command
    cmd = [
        sys.executable, "-m", "daphne",
        "--port", "8000",
        "--bind", "127.0.0.1",
        "ml_model.asgi:application"
    ]
    
    print("Starting ASGI server with Daphne...")
    print(f"Command: {' '.join(cmd)}")
    subprocess.run(cmd)
