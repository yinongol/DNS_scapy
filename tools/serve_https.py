#!/usr/bin/env python3
"""Serve the web/ directory over HTTPS with a self-signed cert.

iOS Safari refuses camera access (getUserMedia) on any origin that isn't
"secure" (HTTPS or localhost). This lets you test the receiver on a real
iPhone over your local WiFi/LAN without any external hosting or accounts.

Usage:
    python3 tools/serve_https.py [port]

Then on the iPhone, open Safari to:
    https://<this-machine's-LAN-IP>:<port>/receive.html
and accept the self-signed certificate warning once.
"""
import http.server
import os
import socket
import ssl
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "web"
CERT_DIR = Path(__file__).resolve().parent / ".certs"
CERT_FILE = CERT_DIR / "cert.pem"
KEY_FILE = CERT_DIR / "key.pem"


def ensure_cert():
    CERT_DIR.mkdir(exist_ok=True)
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    print("Generating self-signed certificate (one-time)...")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(KEY_FILE), "-out", str(CERT_FILE),
            "-days", "365", "-nodes",
            "-subj", "/CN=beamdrop.local",
        ],
        check=True,
    )


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    ensure_cert()
    os.chdir(ROOT)

    httpd = http.server.HTTPServer(("0.0.0.0", port), http.server.SimpleHTTPRequestHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    ip = lan_ip()
    print(f"Serving {ROOT} over HTTPS")
    print(f"  On this machine: https://localhost:{port}/")
    print(f"  On your iPhone (same WiFi): https://{ip}:{port}/receive.html")
    print("  Accept the self-signed certificate warning on first visit.")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
