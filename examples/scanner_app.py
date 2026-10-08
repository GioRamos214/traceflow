"""A slightly richer version of app.py with branches, loops and exceptions,
to exercise every panel of the viewer."""

import json
import time


class ConfigError(Exception):
    pass


class Application:
    def __init__(self, path="settings.json"):
        self.config = load_config(path)
        self.authenticate()

    def authenticate(self):
        if self.config.get("debug"):
            print("Debug mode: skipping auth")
            return True
        print("Initializing application")
        return self.check_token(self.config["token"])

    def check_token(self, token):
        time.sleep(0.01)
        return token.startswith("tok_")

    def main_menu(self):
        choice = input("1. Scan\n2. Reports\n3. Exit\n> ").strip()
        if choice == "1":
            self.scan(["10.0.0.1", "10.0.0.2", "bad-host"])
        elif choice == "2":
            self.reports()
        else:
            print("Goodbye")
        return choice

    def scan(self, hosts):
        results = {}
        for host in hosts:
            try:
                results[host] = probe(host)
            except ValueError as e:
                results[host] = f"error: {e}"
        print(json.dumps(results, indent=2))
        return results

    def reports(self):
        print("No reports yet")


def load_config(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"debug": False, "token": "tok_demo"}


def probe(host):
    parts = host.split(".")
    if len(parts) != 4:
        raise ValueError(f"not an IPv4 address: {host}")
    time.sleep(0.005)
    return "open" if parts[-1] == "1" else "closed"


def main():
    app = Application()
    app.main_menu()


if __name__ == "__main__":
    main()
