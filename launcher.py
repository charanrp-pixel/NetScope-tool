import threading
import webview
import time
import os
import sys
from app import app

def start_server():
    # Run the Flask app on localhost
    app.run(host='127.0.0.1', port=5000, debug=False)

if __name__ == '__main__':
    # Relaunch as root if not root (required for Scapy ARP poisoning and scanning)
    if sys.platform == 'darwin' and os.geteuid() != 0:
        app_path = os.path.abspath(sys.argv[0])
        print("We need administrator privileges to send raw packets. Prompting...")
        # Note: if running from pyinstaller, sys.argv[0] is the executable inside macOS bundle
        command = f'do shell script "\\"{app_path}\\"" with administrator privileges'
        # Run osascript to prompt user, then exit this unprivileged instance
        os.system(f"osascript -e '{command}'")
        sys.exit(0)

    # If run in PyInstaller bundle, change working directory
    # so we can find static and templates folders
    if getattr(sys, 'frozen', False):
        os.chdir(sys._MEIPASS)

    # Start the Flask server in a background thread
    t = threading.Thread(target=start_server)
    t.daemon = True
    t.start()

    # Wait briefly for server to start up
    time.sleep(1.5)

    # Create a native window pointing to the local server
    # This prevents it from opening in a standard web browser
    webview.create_window('NetScope', 'http://127.0.0.1:5000/')
    
    # Start the native window event loop
    webview.start()
