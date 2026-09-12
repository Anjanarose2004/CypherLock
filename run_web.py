import os
import sys
import time
import webbrowser
import threading
from server import app

def open_browser(port):
    time.sleep(1.2)
    url = f"http://127.0.0.1:{port}"
    print(f"[*] Opening browser at {url}...")
    webbrowser.open(url)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 60)
    print("  CYPHER-LOCK STUDIO (Web Edition)")
    print("  AES-256-GCM + RSA-3072 + Digital Signatures")
    print(f"  Starting local server on http://127.0.0.1:{port}")
    print("=" * 60)

    # Automatically launch user's default browser
    threading.Thread(target=open_browser, args=(port,), daemon=True).start()

    # Start Flask application server
    app.run(host="127.0.0.1", port=port, debug=False)
