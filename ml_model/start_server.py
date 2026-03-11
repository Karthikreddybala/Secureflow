#!/usr/bin/env python
"""
Simple Django server startup script for WebSocket support.
This script starts the Django server with Daphne for WebSocket functionality.
"""

import os
import sys
import subprocess
import threading
import time

def start_background_processor():
    """Start the parallel background processors in a separate thread."""
    try:
        print("Starting parallel background processors for ML predictions...")
        # Import here to ensure Django is configured
        from django.core.management import execute_from_command_line
        execute_from_command_line(['manage.py', 'start_background_processor', '--workers', '3'])
    except Exception as e:
        print(f"Error starting background processors: {e}")

def main():
    # Set Django settings module
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ml_model.settings')
    
    print("Starting Django WebSocket Server...")
    print("=" * 50)
    
    # Check if Daphne is installed
    try:
        import daphne
        print("✅ Daphne is installed")
    except ImportError:
        print("❌ Daphne is not installed. Please run: pip install daphne")
        return
    
    # Check if Channels is installed
    try:
        import channels
        print("✅ Channels is installed")
    except ImportError:
        print("❌ Channels is not installed. Please run: pip install channels")
        return
    
    # Start background processor in a separate thread
    bg_thread = threading.Thread(target=start_background_processor, daemon=True)
    bg_thread.start()
    time.sleep(2)  # Give the background processor a moment to start
    
    # Start the server
    try:
        print("Starting server on http://127.0.0.1:8000")
        print("WebSocket endpoints:")
        print("  - Alerts: ws://127.0.0.1:8000/ws/alerts/")
        print("  - Network: ws://127.0.0.1:8000/ws/network/")
        print("\nPress Ctrl+C to stop the server")
        print("=" * 50)
        
        # Run Daphne server
        subprocess.run([
            sys.executable, "-m", "daphne",
            "--port", "8000",
            "--bind", "127.0.0.1",
            "ml_model.asgi:application"
        ])
        
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        print("Make sure you're in the correct directory (secureflow/ml_model/)")

if __name__ == "__main__":
    main() 
