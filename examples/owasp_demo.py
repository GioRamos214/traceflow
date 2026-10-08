"""Deliberately insecure demo for the --security / OWASP screenshot. No prompts.

    python -m traceflow run --security examples/owasp_demo.py "8.8.8.8; whoami" "1+1"

The two arguments stand in for untrusted user input (a host and an expression),
so command injection and code injection are detected. With no arguments it still
shows the other findings. Nothing here is real: the AWS key is Amazon's documented
example value and all secrets are fake.
"""

import hashlib
import os
import pickle
import random
import ssl
import string
import sys

API_KEY = "AKIAIOSFODNN7EXAMPLE"          # A07: hard-coded credential
USERS = {"alice": "5f4dcc3b5aa765d61d8327deb882cf99"}  # md5("password")


def load_credentials():
    # A: reads a cloud credentials file (flagged as sensitive even if it's absent)
    try:
        with open(os.path.expanduser("~/.aws/credentials")) as f:
            return f.read()
    except OSError:
        return None


def make_session_token():
    # A04: predictable randomness used for a secret (function name marks the context)
    return "".join(random.choice(string.ascii_letters) for _ in range(16))


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # A04: weak hash


def authenticate(user, password):
    try:
        return hash_password(password) == USERS[user]
    except Exception:
        return True  # A10: fail-open — an unknown user is let in


def open_insecure_context():
    return ssl._create_unverified_context()  # A02: TLS certificate checking off


def load_cache(blob):
    return pickle.loads(blob)  # A08: unsafe deserialization


def ping(host):
    os.system(f"echo pinging {host}")  # A05: command injection (host is user input)


def calculate(expr):
    return eval(expr)  # A05: code injection (expr is user input)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    expr = sys.argv[2] if len(sys.argv) > 2 else "1+1"

    print("Starting with API key:", API_KEY)   # A09: secret written to output
    load_credentials()
    print("Session:", make_session_token())
    print("Authenticated:", authenticate("mallory", "guess"))
    open_insecure_context()
    load_cache(pickle.dumps({"theme": "dark"}))
    ping(host)
    print("Result:", calculate(expr))


if __name__ == "__main__":
    main()
