"""Security mode: what the program *did* (files, processes, network, dynamic code,
SQL) and findings mapped to the OWASP Top 10:2025.

* SecurityMonitor  - runs during the trace. A ``sys.addaudithook`` hook (PEP 578)
                     sees sensitive operations even deep inside libraries, and a
                     thin sqlite3 wrapper sees SQL text (sqlite3 raises no audit
                     event for queries). Each operation is attached to the call
                     that was running.
* build_report()   - runs afterwards over calls, I/O and activity, and turns them
                     into findings. Detected secrets are then masked everywhere in
                     the trace, because trace files get shared.

Audit hooks are an observability tool, not a sandbox: native code can bypass
them. Run untrusted code in a VM or container.
"""

from __future__ import annotations

import ast
import ipaddress
import os
import re
import sys
import tempfile
import textwrap
import threading
from urllib.parse import urlsplit

from .graph import function_key
from .tracer import _PKG_DIR, _qualname, _under

OWASP = {
    "A01": "A01 Broken Access Control",
    "A02": "A02 Security Misconfiguration",
    "A03": "A03 Software Supply Chain Failures",
    "A04": "A04 Cryptographic Failures",
    "A05": "A05 Injection",
    "A07": "A07 Authentication Failures",
    "A08": "A08 Software or Data Integrity Failures",
    "A09": "A09 Security Logging & Alerting Failures",
    "A10": "A10 Mishandling of Exceptional Conditions",
}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

_AUDIT_KIND = {
    "open": "file", "os.rename": "file",
    "os.remove": "delete", "os.rmdir": "delete", "shutil.rmtree": "delete",
    "subprocess.Popen": "process", "os.system": "process", "os.exec": "process",
    "os.posix_spawn": "process", "os.spawn": "process", "os.startfile": "process",
    "socket.connect": "network", "urllib.Request": "network",
    "compile": "code",
    "ctypes.dlopen": "native",
    "pickle.find_class": "deserialize",
}

_SENSITIVE_PATHS = [(label, re.compile(rx)) for label, rx in [
    ("an SSH key or config", r"/\.ssh/"),
    ("cloud credentials", r"/\.aws/(credentials|config)$|/\.azure/|/gcloud/.*credentials|/\.kube/config$|/\.docker/config\.json$"),
    ("an environment secrets file", r"/\.env(\.[^/]*)?$"),
    ("stored credentials", r"/\.git-credentials$|/[._]netrc$|/\.pgpass$|/\.npmrc$|/\.pypirc$"),
    ("a private key or certificate", r"\.(pem|key|pfx|p12|jks|keystore)$|/id_(rsa|dsa|ecdsa|ed25519)[^/]*$"),
    ("a GPG keyring", r"/\.gnupg/"),
    ("the system account database", r"^/etc/(passwd|shadow|gshadow|sudoers)$|/windows/system32/config/(sam|security|system)$"),
    ("the Windows credential store", r"/microsoft/(credentials|protect|vault)/"),
    ("browser passwords or cookies", r"/(login data|cookies|web data)$|/logins\.json$|/key[34]\.db$|/cookies\.sqlite$"),
    ("the macOS keychain", r"/library/keychains/"),
]]

_SECRET_PATTERNS = [(label, re.compile(rx)) for label, rx in [
    ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"),
    ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    ("Stripe key", r"\b[sr]k_live_[A-Za-z0-9]{20,}"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}"),
    ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}"),
    ("private key", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
]]
_SECRET_NAMES = r"password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|token|private[_-]?key|client[_-]?secret"
# key = value in output / URLs / commands, and key = "value" in source code
_GENERIC_KV = re.compile(rf"(?i)\b(?:{_SECRET_NAMES})\b\s*[:=]\s*([A-Za-z0-9_\-+/=.~]{{8,}})")
_GENERIC_SRC = re.compile(rf"(?i)\b\w*(?:{_SECRET_NAMES})\w*\s*[:=]\s*[rbuf]?(['\"])([^'\"\s]{{8,}})\1")
_URL_SECRET = re.compile(r"(?i)[?&](?:token|access_token|api_?key|key|secret|password|pass|auth|sig|signature)=([^&#\s]{6,})")
_URL_PASSWORD = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s:@]{3,})@")
_PLACEHOLDER = re.compile(r"(?i)example|changeme|placeholder|your[_-]|xxxx|dummy|sample|redacted|\*\*\*|<|\{")
_SECRET_ENV = re.compile(r"(?i)key|token|secret|pass|pwd|credential|auth|private")
_SECURITY_NAME = re.compile(r"(?i)auth|login|logon|passw|pwd|token|secret|session|verif|valid|check|permission|allow|"
                            r"admin|access|sign|credential|key|nonce|salt|otp|csrf|reset")
_HTML_TAG = re.compile(r"<[a-zA-Z][a-zA-Z0-9]*[\s>/]")
_DESERIALIZERS = {"_pickle.loads", "_pickle.load", "pickle.loads", "pickle.load", "marshal.loads", "marshal.load",
                  "yaml.unsafe_load", "yaml.full_load", "dill.loads", "dill.load", "jsonpickle.decode", "shelve.open"}


class InterceptDropped(PermissionError):
    """Raised into the program when an intercepted operation is dropped in the live viewer."""


def sensitive_label(path: str) -> str | None:
    norm = _norm_path(path)
    return next((label for label, rx in _SENSITIVE_PATHS if rx.search(norm)), None)


def mask(value: str) -> str:
    value = str(value)
    return value[:4] + "…" + value[-2:] if len(value) > 10 else value[:2] + "…"


def _env_secrets() -> dict[str, str]:
    out = {}
    for k, v in os.environ.items():
        if (_SECRET_ENV.search(k) and len(v) >= 8 and " " not in v and ";" not in v
                and not v.startswith("/") and not re.match(r"^[A-Za-z]:[\\/]", v)):
            out[v] = f"value of ${k}"
    return out


def _plausible(value: str) -> bool:
    """Filter out placeholders and plain words from generic key=value matches."""
    if _PLACEHOLDER.search(value) or len(set(value)) < 4:
        return False
    return any(ch.isdigit() for ch in value) or (any(ch.isupper() for ch in value) and any(ch.islower() for ch in value))


def _is_loopback(host: str) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _norm_path(p: str) -> str:
    return os.path.abspath(p).replace("\\", "/").lower()


def _decode(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", "replace")
    return os.fspath(v) if isinstance(v, os.PathLike) else str(v)


# =============================================================== runtime monitor
class SecurityMonitor:
    MAX_ACTIVITY = 10_000

    def __init__(self, tracer):
        self.tracer = tracer
        self.activity: list[dict] = []
        self.truncated = False
        self.active = False
        self.env_secrets: dict[str, str] = {}
        self._tl = threading.local()
        self._installed = False
        self._origin: dict[str, str] = {}
        self._restore_sqlite = None
        self.ctl = None  # live.Controller: intercept rules (pause, forward, drop)

    def start(self):
        self.env_secrets.update(_env_secrets())
        self._patch_sqlite()
        if not self._installed:
            sys.addaudithook(self._hook)  # audit hooks can't be removed; `active` switches it off
            self._installed = True
        self.active = True

    def stop(self):
        self.active = False
        self.env_secrets.update(_env_secrets())  # picks up secrets the program loaded itself, e.g. from .env
        if self._restore_sqlite:
            self._restore_sqlite()
            self._restore_sqlite = None

    # ---------------------------------------------------------------- hooks
    def _hook(self, event, args):
        kind = _AUDIT_KIND.get(event)
        if kind is None or not self.active or getattr(self._tl, "busy", False):
            return
        self._tl.busy = True
        try:
            entry = self._describe(kind, event, args)
            if entry:
                self._observe(entry, sys._getframe(1))
        except InterceptDropped:
            raise  # the user dropped this operation in the live viewer: the program gets the error
        except Exception:  # never break the program being traced
            pass
        finally:
            self._tl.busy = False

    def _sql(self, sql, parameters, frame):
        if not self.active or getattr(self._tl, "busy", False):
            return
        self._tl.busy = True
        try:
            has_params = parameters if isinstance(parameters, bool) else bool(parameters)
            self._observe({"kind": "database", "op": "sql", "target": _decode(sql)[:2000], "params": has_params}, frame)
        except InterceptDropped:
            raise
        except Exception:
            pass
        finally:
            self._tl.busy = False

    def _classify(self, filename: str) -> str:
        c = self._origin.get(filename)
        if c is None:
            if filename.startswith(("<frozen importlib", "<frozen zipimport")):
                c = "import"
            elif filename.startswith("<"):
                c = "other"
            elif _under(os.path.abspath(filename), _PKG_DIR):
                c = "pkg"
            elif self.tracer._is_user_file(filename):
                c = "user"
            else:
                c = "other"
            self._origin[filename] = c
        return c

    def _observe(self, entry: dict, frame):
        """Find the user frame responsible. Imports and traceflow's own work are ignored."""
        f, user, direct = frame, None, True
        while f is not None:
            c = self._classify(f.f_code.co_filename)
            if c in ("import", "pkg"):
                return
            if c == "user":
                user = f
                break
            direct = False
            f = f.f_back
        if entry["kind"] == "code" and not direct:
            return  # stdlib helpers that generate code (namedtuple, dataclasses)
        if len(self.activity) >= self.MAX_ACTIVITY:
            self.truncated = True
            return
        stack = self.tracer._stack()
        entry.update(
            seq=len(self.tracer.events), t=self.tracer._now(), call=stack[-1] if stack else None,
            file=user.f_code.co_filename if user else None, line=user.f_lineno if user else None,
            func=_qualname(user.f_code) if user else None,
            sensitive=bool(entry.get("path") and sensitive_label(entry["path"])),
        )
        self.activity.append(entry)
        if self.ctl is not None and self.ctl.intercepts:
            decision = self.ctl.intercept(entry, user)
            if decision is not None:
                entry["decision"] = "dropped" if decision.get("drop") else "forwarded"
                if decision.get("drop"):
                    raise InterceptDropped(f"Blocked in the traceflow viewer: {entry['kind']} {entry['op']} {entry['target'][:200]}")

    @staticmethod
    def _describe(kind, event, args) -> dict | None:
        e = {"kind": kind, "event": event}
        if event == "open":
            path, mode, flags = (list(args) + [None, None])[:3]
            if isinstance(path, int):
                return None
            if isinstance(mode, str):
                write = any(ch in mode for ch in "wax+")
            else:
                write = bool((flags or 0) & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT))
            e.update(op="write" if write else "read", target=_decode(path), path=_decode(path), write=write)
        elif event == "os.rename":
            src, dst = _decode(args[0]), _decode(args[1])
            e.update(op="rename", target=f"{src} → {dst}", path=dst, write=True)
        elif kind == "delete":
            e.update(op="delete", target=_decode(args[0]), path=_decode(args[0]))
        elif event == "subprocess.Popen":
            cmd = args[1]
            cmd = _decode(cmd) if isinstance(cmd, (str, bytes, os.PathLike)) else " ".join(_decode(a) for a in cmd)
            e.update(op="run", target=cmd)
        elif event == "os.system":
            e.update(op="shell", target=_decode(args[0]))
        elif event in ("os.exec", "os.posix_spawn"):
            argv = args[1] or []
            e.update(op="exec", target=" ".join(_decode(a) for a in argv) or _decode(args[0]))
        elif event == "os.spawn":
            e.update(op="spawn", target=" ".join(_decode(a) for a in (args[2] or [])) or _decode(args[1]))
        elif event == "os.startfile":
            e.update(op="startfile", target=_decode(args[0]))
        elif event == "socket.connect":
            addr = args[1]
            if isinstance(addr, tuple) and len(addr) >= 2:
                host, port = str(addr[0]), addr[1]
                e.update(op="connect", target=f"[{host}]:{port}" if ":" in host else f"{host}:{port}", host=host, port=port)
            else:
                e.update(op="connect", target=_decode(addr), host=None)
        elif event == "urllib.Request":
            url = _decode(args[0])
            e.update(op=(args[3] or "GET") if len(args) > 3 else "GET", target=url, url=url, host=urlsplit(url).hostname)
        elif event == "compile":
            source, filename = args[0], _decode(args[1])
            if not filename.startswith("<") or not isinstance(source, (str, bytes, bytearray)):
                return None
            e.update(op="eval/exec", target=_decode(source)[:2000])
        elif event == "ctypes.dlopen":
            e.update(op="load", target=_decode(args[0]))
        elif event == "pickle.find_class":
            e.update(op="unpickle class", target=f"{args[0]}.{args[1]}")
        else:
            return None
        e["target"] = e["target"][:2000]
        return e

    def _patch_sqlite(self):
        try:
            import sqlite3
        except ImportError:
            return
        mon = self

        class Cursor(sqlite3.Cursor):
            def execute(self, sql, parameters=(), /):
                mon._sql(sql, parameters, sys._getframe(1))
                return super().execute(sql, parameters)

            def executemany(self, sql, seq_of_parameters, /):
                mon._sql(sql, True, sys._getframe(1))
                return super().executemany(sql, seq_of_parameters)

            def executescript(self, sql_script, /):
                mon._sql(sql_script, (), sys._getframe(1))
                return super().executescript(sql_script)

        class Connection(sqlite3.Connection):
            def cursor(self, factory=Cursor):
                return super().cursor(factory)

            def execute(self, sql, parameters=(), /):
                mon._sql(sql, parameters, sys._getframe(1))
                return super().execute(sql, parameters)

            def executemany(self, sql, seq_of_parameters, /):
                mon._sql(sql, True, sys._getframe(1))
                return super().executemany(sql, seq_of_parameters)

            def executescript(self, sql_script, /):
                mon._sql(sql_script, (), sys._getframe(1))
                return super().executescript(sql_script)

        original = sqlite3.connect

        def connect(*args, **kwargs):
            if "factory" not in kwargs and len(args) < 6:  # factory is the 6th positional parameter
                kwargs["factory"] = Connection
            return original(*args, **kwargs)

        sqlite3.connect = sqlite3.dbapi2.connect = connect

        def restore():
            sqlite3.connect = sqlite3.dbapi2.connect = original

        self._restore_sqlite = restore


# ===================================================================== analysis
class _Report:
    def __init__(self, trace: dict, activity: list, env_secrets: dict, root: str, lang: str = "python"):
        self.calls, self.events, self.sources = trace["calls"], trace["events"], trace["sources"]
        self.meta = trace["meta"]
        self.activity = activity
        self.env_secrets = env_secrets
        self.root = root
        self.lang = lang
        self.findings: list[dict] = []
        self.secrets: dict[str, str] = {}  # raw value -> label, for redaction
        self._seen: set = set()
        self.inputs = [(e["seq"], e["t"], e["text"].strip()) for e in self.events
                       if e["type"] == "stdin" and len(e["text"].strip()) >= 3 and e["text"] != "<EOF>"]
        self.inputs += [(-1, -1, a) for a in self.meta.get("argv") or [] if len(a) >= 3]

    def _fix(self, py: str, js: str) -> str:
        return js if self.lang == "javascript" else py

    # ---------------------------------------------------------------- helpers
    def add(self, rule, owasp, severity, title, detail, fix=None, call=None, file=None, line=None,
            evidence=None, dedupe=None, **extra):
        key = (rule, dedupe if dedupe is not None else (call, file, line, evidence))
        if key in self._seen:
            return
        self._seen.add(key)
        if (file is None or line is None) and call is not None:
            c = self.calls[call]
            file, line = (c["caller_file"], c["caller_line"]) if c["kind"] in ("builtin", "library") else (c["file"], c["def_line"])
        self.findings.append({
            "rule": rule, "owasp": owasp, "category": OWASP.get(owasp, "Runtime behavior"), "severity": severity,
            "title": title, "detail": detail, "fix": fix, "call": call, "file": file, "line": line,
            "evidence": evidence[:300] if evidence else None, **extra,
        })

    def scan_secrets(self, text: str, source_code=False) -> list[tuple[str, str]]:
        found, spans = [], []

        def take(label, value, start):
            end = start + len(value)
            if any(s < end and start < e for s, e in spans):
                return
            spans.append((start, end))
            found.append((label, value))
            self.secrets.setdefault(value, label)

        for label, rx in _SECRET_PATTERNS:
            for m in rx.finditer(text):
                take(label, m.group(0), m.start())
        if source_code:
            for m in _GENERIC_SRC.finditer(text):
                if _plausible(m.group(2)):
                    take("possible secret", m.group(2), m.start(2))
        else:
            for m in _GENERIC_KV.finditer(text):
                if _plausible(m.group(1)):
                    take("possible secret", m.group(1), m.start(1))
            for rx in (_URL_PASSWORD, _URL_SECRET):
                for m in rx.finditer(text):
                    take("credential in URL", m.group(1), m.start(1))
            for value, label in self.env_secrets.items():
                i = text.find(value)
                if i >= 0:
                    take(label, value, i)
        return found

    def tainted(self, text: str, seq=None, t=None):
        """Return the user input that appears in `text` and was read before it was used."""
        for s, ts, value in self.inputs:
            if (seq is None or s < seq) and (t is None or ts < t) and value in text:
                return value
        return None

    def outside_project(self, path: str) -> bool:
        p = os.path.abspath(path)
        return not _under(p, self.root) and not _under(p, tempfile.gettempdir())

    def add_raw(self, f: dict):
        """Add a pre-formed finding (e.g. from the Node recorder), with dedupe and category."""
        self.add(f["rule"], f.get("owasp"), f["severity"], f["title"], f["detail"], fix=f.get("fix"),
                 call=f.get("call"), file=f.get("file"), line=f.get("line"), evidence=f.get("evidence"),
                 dedupe=tuple(f["dedupe"]) if isinstance(f.get("dedupe"), list) else f.get("dedupe"),
                 **{k: v for k, v in f.items() if k == "refs"})

    # ------------------------------------------------------------------ rules
    def run(self):
        self.secret_rules()
        self.activity_rules()
        self.xss_rule()
        if self.lang == "python":  # these rules read Python library calls / Python AST
            self.call_rules()
            self.exception_rules()

    def secret_rules(self):
        for e in self.events:
            if e["type"] not in ("stdout", "stderr"):
                continue
            for label, value in self.scan_secrets(e["text"]):
                where = "the program output" if e["type"] == "stdout" else "the error output (stderr)"
                self.add("secret.output", "A09", "high", f"Secret written to {where}",
                         f"A {label} was printed. Printed text ends up in terminals, log files, CI logs and bug reports.",
                         fix="Never print or log secrets. Log a masked form (first 4 characters) if you need to identify which key was used.",
                         call=e["call"], evidence=e["text"].strip(), dedupe=(value, e["type"]))
        for c in self.calls:
            if c["kind"] == "library" and (c["module"] or "").startswith("logging") and c["args"]:
                text = " ".join(c["args"].values())
                for label, value in self.scan_secrets(text):
                    self.add("secret.log", "A09", "high", "Secret passed to the logger",
                             f"A {label} was handed to {c['qualname']}. Log files are kept for a long time and read by many people.",
                             fix="Remove the secret from the log call or mask it.", call=c["id"], evidence=text, dedupe=value)
        first_call = {}
        for c in self.calls:
            if c["source"]:
                first_call.setdefault(c["source"], c["id"])
        for key, src in self.sources.items():
            for i, text in enumerate(src["lines"]):
                if text.lstrip().startswith(("#", "//", "*")):  # Python and JS/TS comment lines
                    continue
                for label, value in self.scan_secrets(text, source_code=True):
                    generic = label == "possible secret"
                    self.add("secret.hardcoded", "A07", "medium" if generic else "high",
                             "Possible hard-coded secret" if generic else f"Hard-coded {label}",
                             "A credential is written directly in the source code. Anyone who can read the code or its "
                             "git history can use it, and it can't be rotated without a code change.",
                             fix="Load it from an environment variable or a secrets manager, and rotate the exposed value.",
                             call=first_call.get(key), file=src["file"], line=src["start"] + i, evidence=text.strip(),
                             dedupe=(src["file"], src["start"] + i))

    def activity_rules(self):
        for a in self.activity:
            kind, target, seq = a["kind"], a["target"], a["seq"]
            loc = dict(call=a["call"], file=a["file"], line=a["line"])
            t = self.tainted(target, seq=seq)
            if kind == "process":
                if t:
                    self.add("injection.command", "A05", "high", "User input reaches a system command",
                             f"Text the user typed ({t!r}) became part of a command that was executed. Characters like "
                             "; & | ` $( let an attacker run any command they want.",
                             fix=self._fix("Pass arguments as a list to subprocess.run() without shell=True, and validate the input against an allow-list.",
                                           "Use execFile/spawn with an args array and no shell, and validate the input against an allow-list."),
                             evidence=target, **loc)
                for label, value in self.scan_secrets(target):
                    self.add("secret.command", "A04", "medium", "Secret on a command line",
                             f"A {label} was passed as a command-line argument. Other users and processes on the machine "
                             "can read command lines, and they are often logged.",
                             fix="Pass secrets to child processes through environment variables or stdin.",
                             evidence=target, dedupe=value, **loc)
            elif kind == "code":
                if t:
                    self.add("injection.code", "A05", "high", f"User input executed as {'JavaScript' if self.lang == 'javascript' else 'Python'} code",
                             f"Text the user typed ({t!r}) was run with eval/exec. That gives them full control of the program.",
                             fix=self._fix("Don't eval input. For arithmetic use ast.literal_eval or a small parser; for data use json.loads.",
                                           "Don't eval input. Use JSON.parse for data, or a small parser/lookup table for anything else."),
                             evidence=target, **loc)
                else:
                    self.add("code.dynamic", "A05", "low", "Code built from a string and executed",
                             "eval/exec ran a string. It's safe only as long as no outside data can ever reach that string.",
                             fix="Prefer a direct function call or a lookup table over eval/exec.", evidence=target, **loc)
            elif kind == "database":
                if t and not a.get("params"):
                    self.add("injection.sql", "A05", "high", "SQL injection: user input inside a query",
                             f"Text the user typed ({t!r}) was pasted into the SQL text instead of being passed as a parameter.",
                             fix=self._fix('Use placeholders: cursor.execute("... WHERE name = ?", (name,)).',
                                           'Use parameterised queries: db.query("... WHERE name = ?", [name]).'),
                             evidence=target, **loc)
            elif kind in ("file", "delete"):
                path = a.get("path") or target
                if t:
                    traversal = any(x in t for x in ("..", "/", "\\")) or os.path.isabs(t)
                    self.add("path.traversal", "A01", "high" if traversal else "medium", "File path built from user input",
                             f"Text the user typed ({t!r}) chose which file was {'deleted' if kind == 'delete' else 'opened'}. "
                             "With ../ an attacker can reach files outside the intended folder.",
                             fix=self._fix("Resolve the path and check it's inside the allowed folder (Path.resolve().is_relative_to(base)).",
                                           "Resolve the path and check it's inside the allowed folder (path.resolve(base, name).startsWith(base))."),
                             evidence=target, **loc)
                norm = _norm_path(path)
                for label, rx in _SENSITIVE_PATHS:
                    if rx.search(norm):
                        verb = {"delete": "deleted", "write": "wrote to", "rename": "renamed"}.get(a["op"], "read")
                        self.add("file.sensitive", None, "high", f"Program {verb} {label}",
                                 f"{os.path.basename(path)} usually holds credentials. Make sure this access is expected; "
                                 "unexpected reads of files like this are a classic sign of malicious code.",
                                 evidence=path, dedupe=(norm, a["op"]), **loc)
                        break
                if kind == "delete" and self.outside_project(path):
                    self.add("file.delete_outside", None, "medium", "Deleted a file outside the project",
                             "The program removed something outside its own folder and the temp directory.", evidence=path, **loc)
                elif a.get("write") and self.outside_project(path):
                    self.add("file.write_outside", None, "low", "Wrote a file outside the project",
                             "The program created or changed a file outside its own folder and the temp directory.",
                             evidence=path, dedupe=_norm_path(path), **loc)
            elif kind == "network":
                host, url = a.get("host"), a.get("url")
                if t:
                    self.add("ssrf", "A01", "high", "User input controls a network destination (SSRF)",
                             f"Text the user typed ({t!r}) decided where the program connected. An attacker can point it at "
                             "internal services or cloud metadata endpoints.",
                             fix="Only allow known hosts, and block private and loopback addresses.", evidence=target, **loc)
                if url:
                    plain = urlsplit(url).scheme == "http" and not _is_loopback(host)
                    for label, value in self.scan_secrets(url):
                        self.add("secret.url", "A04", "high" if plain else "medium",
                                 "Secret sent unencrypted" if plain else "Secret in a URL",
                                 f"A {label} is part of the URL. URLs are recorded by servers, proxies and browser history"
                                 + (", and this one went over plain HTTP." if plain else "."),
                                 fix="Send secrets in a header (Authorization: Bearer …) over HTTPS, never in the query string.",
                                 evidence=url, dedupe=value, **loc)
                    if plain:
                        self.add("net.cleartext", "A04", "medium", "Unencrypted HTTP request",
                                 f"Data sent to {host} can be read or changed by anyone on the network path.",
                                 fix="Use https://.", evidence=url, dedupe=host, **loc)

    def xss_rule(self):
        risky = [(s, ts, v) for s, ts, v in self.inputs if any(ch in v for ch in "<>\"'")]
        if not risky:
            return

        def check(text, call, seq=None, t=None):
            if not _HTML_TAG.search(text):
                return
            for s, ts, value in risky:
                if (seq is None or s < seq) and (t is None or ts < t) and value in text:
                    self.add("injection.xss", "A05", "high", "Cross-site scripting: user input placed in HTML unescaped",
                             f"Text the user typed ({value!r}) appears as-is inside HTML. In a browser, a <script> tag in it would run.",
                             fix=self._fix("Escape with html.escape(), or use a template engine with auto-escaping (Jinja2 autoescape=True).",
                                           "Escape user input before putting it in HTML, or use a templating library with auto-escaping. Don't set innerHTML from input."),
                             call=call, evidence=text, dedupe=value)

        for c in self.calls:
            if c["kind"] in ("python", "generator", "js") and c["return"]:
                check(c["return"], c["id"], t=c["end"])
        for e in self.events:
            if e["type"] == "stdout":
                check(e["text"], e["call"], seq=e["seq"])

    def call_rules(self):
        for c in self.calls:
            if c["kind"] not in ("builtin", "library"):
                continue
            q, args = c["qualname"], c["args"] or {}
            parent = self.calls[c["parent"]] if c["parent"] is not None else None
            security_context = bool(parent and _SECURITY_NAME.search(parent["qualname"]))
            argtext = " ".join(f"{k}={v}" for k, v in args.items())
            m = re.search(r"(?:^|[._])(md5|sha1)$", q)
            alg = m.group(1) if m else None
            if not alg and q.endswith(("hashlib.new", "hashlib.__hash_new")):
                m = re.search(r"md5|sha1", str(args.get("name", "")), re.I)
                alg = m.group(0).lower() if m else None
            if alg:
                self.add("crypto.weak_hash", "A04", "medium" if security_context else "low", f"Weak hash algorithm ({alg.upper()})",
                         f"{alg.upper()} is broken for security use: collisions are cheap and it is far too fast for passwords"
                         + (f" (used in {parent['qualname']})." if parent else "."),
                         fix="Passwords: hashlib.scrypt, argon2 or bcrypt. Integrity checks: hashlib.sha256.",
                         call=c["id"], dedupe=(function_key(parent) if parent else None, alg))
            if (q.startswith(("random.", "_random.")) or c["module"] == "random") and security_context:
                self.add("crypto.weak_random", "A04", "medium", "Predictable random numbers used for a secret",
                         f"{parent['qualname']} uses the random module, which is predictable: someone who sees a few outputs can "
                         "work out the rest.", fix="Use the secrets module (secrets.token_urlsafe(), secrets.choice()).",
                         call=c["id"], dedupe=function_key(parent))
            if "_create_unverified_context" in q or re.search(r"(?:^|[\s,{'])(verify|check_hostname)'?\s*[=:]\s*False", argtext):
                self.add("config.tls_disabled", "A02", "high", "TLS certificate checking turned off",
                         "Without certificate checks, anyone on the network can impersonate the server and read or change the traffic.",
                         fix="Remove verify=False / unverified contexts. For internal CAs, pass the CA bundle instead.",
                         call=c["id"], evidence=f"{q}({argtext})")
            if c["kind"] == "library" and re.search(r"(?:^|[\s,{'])debug'?\s*[=:]\s*True", argtext):
                self.add("config.debug", "A02", "medium", "Debug mode enabled",
                         f"{q} was called with debug=True. Debug modes leak stack traces and internals, and some (Flask/Werkzeug) "
                         "allow running code from the browser.", fix="Turn debug off outside local development.",
                         call=c["id"], evidence=f"{q}({argtext})")
            if q in _DESERIALIZERS or (q == "yaml.load" and "Safe" not in str(args.get("Loader", ""))):
                self.add("integrity.deserialization", "A08", "medium", "Unsafe deserialization",
                         f"{q} can run arbitrary code if the data was crafted by an attacker.",
                         fix="Use json for data from outside. If you must use pickle, sign the data (hmac) and verify before loading.",
                         call=c["id"], dedupe=(function_key(parent) if parent else None, q))

    def exception_rules(self):
        cache: dict[str, list] = {}
        for c in self.calls:
            if c["kind"] not in ("python", "generator") or not c["handled"] or not c["source"]:
                continue
            if c["source"] not in cache:
                cache[c["source"]] = _handlers(self.sources.get(c["source"], {}))
            security_context = bool(_SECURITY_NAME.search(c["qualname"]))
            for h in c["handled"]:
                hd = next((x for x in cache[c["source"]] if h.get("caught_at") in (x["line"], x["first"])), None)
                if not hd:
                    continue
                what = f"{h['type']} ({h['message']}) was raised at line {h['line']} and caught by `{hd['text']}`"
                if hd["behaviour"] == "fail_open":
                    self.add("exceptions.fail_open", "A10", "high" if security_context else "medium",
                             "Error turned into success (fail-open)",
                             f"This happened during the run: {what}, which then reported success. If anything goes wrong in "
                             f"{c['qualname']}, the check passes.",
                             fix="On error, deny: return False / raise. Catch only the specific exceptions you expect.",
                             call=c["id"], line=hd["line"], file=c["file"], evidence=hd["text"], dedupe=(c["source"], hd["line"]))
                elif hd["behaviour"] == "swallow" and hd["broad"]:
                    self.add("exceptions.swallowed", "A10", "medium" if security_context else "low", "Error silently swallowed",
                             f"This happened during the run: {what}, which ignores it. Failures go unnoticed and the program "
                             "carries on in an unknown state.",
                             fix="Catch specific exceptions, and log or re-raise the rest.",
                             call=c["id"], line=hd["line"], file=c["file"], evidence=hd["text"], dedupe=(c["source"], hd["line"]))

    def package_rules(self, packages: list[dict]):
        first_call = {}
        for c in self.calls:
            if c["kind"] == "library" and c["module"]:
                first_call.setdefault(c["module"].split(".")[0], c["id"])
        rank = {"critical": "high", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}
        for p in packages:
            vulns = p.get("vulns") or []
            if not vulns:
                continue
            sev = min((rank.get((v.get("severity") or "").lower(), "medium") for v in vulns), key=SEVERITY_ORDER.get)
            fixed = sorted({f for v in vulns for f in v.get("fixed", [])}, key=_version_key)
            call = next((first_call[m] for m in p["modules"] if m in first_call), None)
            self.add("supply_chain.vulnerable", "A03", sev,
                     f"{p['name']} {p['version']}: {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}",
                     ("Your code called this package directly during the run." if p.get("called")
                      else "It was imported during the run (possibly by another package).")
                     + (f" Fixed in: {', '.join(fixed[:4])}." if fixed else ""),
                     fix=f"Upgrade {p['name']}" + (f" to {fixed[-1]} or later." if fixed else "."),
                     call=call, evidence=", ".join(v["id"] for v in vulns[:6]), dedupe=p["name"],
                     refs=[{"id": v["id"], "summary": v.get("summary") or ""} for v in vulns[:12]])


def _version_key(v: str):
    """Sort 2.9 before 2.10 (good enough without pulling in `packaging`)."""
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.\-+]", v)]


def _is_broad(node) -> bool:
    names = {"Exception", "BaseException"}
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.Tuple):
        return any(_is_broad(e) for e in node.elts)
    return False


def _handlers(src: dict) -> list[dict]:
    """Except handlers in one code object's source, with what each one does."""
    lines = src.get("lines") or []
    if not lines:
        return []
    off = src["start"] - 1
    try:
        tree = ast.parse(textwrap.dedent("\n".join(lines)))
    except SyntaxError:
        return []
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.ExceptHandler):
            continue
        behaviour = None
        if all(isinstance(s, (ast.Pass, ast.Continue)) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
               for s in n.body):
            behaviour = "swallow"
        for s in (x for stmt in n.body for x in ast.walk(stmt)):
            if isinstance(s, ast.Return) and isinstance(s.value, ast.Constant) and s.value.value is True:
                behaviour = "fail_open"
            elif (isinstance(s, ast.Assign) and isinstance(s.value, ast.Constant) and s.value.value is True and any(
                    isinstance(t, ast.Name) and re.search(r"(?i)auth|allow|valid|ok|admin|logged|success|grant|permit", t.id)
                    for t in s.targets)):
                behaviour = "fail_open"
        out.append({"line": n.lineno + off, "first": (n.body[0].lineno if n.body else n.lineno) + off,
                    "broad": n.type is None or _is_broad(n.type), "behaviour": behaviour,
                    "text": lines[n.lineno - 1].strip() if n.lineno <= len(lines) else "except"})
    return out


def _redact(obj, values: list[str], hit: set):
    if isinstance(obj, str):
        for v in values:
            if v in obj:
                obj = obj.replace(v, mask(v))
                hit.add(v)
        return obj
    if isinstance(obj, list):
        return [_redact(x, values, hit) for x in obj]
    if isinstance(obj, dict):
        return {k: _redact(v, values, hit) for k, v in obj.items()}
    return obj


def build_report(trace: dict, activity: list, env_secrets: dict, root: str, packages: list[dict] | None,
                 package_note: str | None, lang: str = "python", extra_findings: list | None = None,
                 truncated: bool = False, redact: bool = True) -> dict:
    r = _Report(trace, activity, env_secrets, root, lang=lang)
    r.run()
    for f in extra_findings or []:  # language-specific findings from the recorder (e.g. Node sinks)
        r.add_raw(f)
    r.package_rules(packages or [])
    r.findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]],
                                   trace["calls"][f["call"]]["start"] if f["call"] is not None
                                   and f["call"] < len(trace["calls"]) else float("inf")))
    out_activity = [{k: v for k, v in a.items() if k != "seq"} for a in activity]
    notes = []
    if truncated:
        notes.append("Activity log was truncated (too many entries).")
    if package_note:
        notes.append(package_note)
    report = {
        "findings": r.findings, "activity": out_activity, "packages": packages or [], "notes": notes,
        "summary": {s: sum(f["severity"] == s for f in r.findings) for s in SEVERITY_ORDER},
        "redacted": 0,
    }
    # Mask everything detected, plus every secret-named environment value even if it never leaked:
    # it can still sit in captured arguments and return values (e.g. the text of a .env file).
    secrets = set(r.secrets) | set(env_secrets)
    if redact and secrets:
        values = sorted((v for v in secrets if len(v) >= 6), key=len, reverse=True)
        hit: set = set()
        for key in ("calls", "events", "sources", "meta"):
            trace[key] = _redact(trace[key], values, hit)
        report = _redact(report, values, hit)
        report["redacted"] = len(hit)  # only secrets that actually appeared in the trace
    return report
