"""A deliberately insecure app for trying `traceflow run --security`.

Every function below contains one classic mistake. Nothing leaves your machine:
the "network" part talks to a tiny server this script starts on 127.0.0.1, and
the secrets are fake (the AWS key is Amazon's documented example key).

Run it and answer the prompts, e.g. with the values in inputs.txt:
    traceflow run --security examples/insecure/app.py
"""

import hashlib
import http.server
import os
import pickle
import random
import sqlite3
import ssl
import string
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"          # hard-coded credential
USERS = {"alice": "5f4dcc3b5aa765d61d8327deb882cf99"}  # md5("password")


def load_settings():
    """Reads a .env file (sensitive file access) into the environment."""
    for line in (Path(__file__).with_name(".env")).read_text().splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            os.environ[key] = value
    print(f"Loaded settings, using token {os.environ['DEMO_API_TOKEN']}")  # secret printed


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # weak hash for passwords


def login(username, password):
    try:
        return hash_password(password) == USERS[username]
    except Exception:
        return True  # fail-open: an unknown user is let in


def make_session_token():
    return "".join(random.choice(string.ascii_letters) for _ in range(24))  # predictable


def find_user(db, name):
    return db.execute(f"SELECT id, name FROM users WHERE name = '{name}'").fetchall()  # SQL injection


def render_profile(name):
    return f"<h1>Welcome, {name}</h1>"  # XSS: not escaped


def ping(host):
    os.system(f"echo pinging {host}")  # command injection


def calculator(expression):
    return eval(expression)  # code injection


def check_status(token):
    class Quiet(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    server = http.server.HTTPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=server.handle_request, daemon=True).start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = f"http://127.0.0.1:{server.server_port}/status?token={token}"  # secret in URL
    with opener.open(url, timeout=5) as resp:
        status = resp.read().decode()
    server.server_close()
    return status


def insecure_tls_context():
    return ssl._create_unverified_context()  # certificate checks off


def load_cache(blob):
    return pickle.loads(blob)  # unsafe deserialization


def run_helper():
    subprocess.run([sys.executable, "-c", "print('helper process ran')"], check=True)


def main():
    load_settings()
    username = input("Username: ")
    print("Logged in" if login(username, "guess") else "Access denied")
    print("Session:", make_session_token())

    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    name = input("Display name: ")
    print(find_user(db, name))
    print(render_profile(name))

    ping(input("Host to ping: "))
    print("Result:", calculator(input("Expression: ")))
    print("Status:", check_status(os.environ["DEMO_API_TOKEN"]))
    insecure_tls_context()
    print("Cache:", load_cache(pickle.dumps({"theme": "dark"})))
    run_helper()


if __name__ == "__main__":
    main()
