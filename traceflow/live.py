"""Live mode: stream the trace to the browser while the program runs, and pause it.

* Controller  - called from the tracer and the security monitor on the program's own
                threads. When a breakpoint, step or intercept rule matches, that thread
                blocks on a Condition until the viewer sends a decision; other threads
                that reach traced code meanwhile wait too, so nothing changes underneath
                you. Time spent paused is taken out of the timings.
* LiveServer  - a one-thread HTTP server on 127.0.0.1. The viewer polls it for what
                changed. Started before tracing, so its thread is never traced. Every API
                call needs the per-run secret token, the Host header must be the loopback
                address (DNS rebinding), and control requests must be JSON (cross-site pages
                can't send that without a CORS preflight this server never approves).

Editing values works by writing to frame.f_locals from inside the trace callback:
CPython writes the dict back to the frame when the callback returns (and on 3.13+
f_locals writes through directly). Read f_locals once and apply all edits to that
one dict: each fresh read re-syncs from the frame and drops earlier edits.
"""

from __future__ import annotations

import ast
import http.server
import json
import os
import secrets
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

from . import graph, render
from .tracer import _qualname, safe_repr

INTERCEPTS = {
    "process": "Processes started",
    "network": "Network requests",
    "file_write": "File writes",
    "delete": "File deletes",
    "sensitive": "Sensitive files (.env, .ssh, …)",
    "sql": "SQL queries",
    "code": "eval / exec",
}
STEP_ACTIONS = ("step_into", "step_over", "step_out")


def _say(msg: str):
    # sys.stderr is wrapped by the tracer while the program runs; talk to the real terminal
    try:
        print(f"[traceflow] {msg}", file=sys.__stderr__, flush=True)
    except Exception:
        pass


class Controller:
    def __init__(self, tracer):
        self.tracer = tracer
        self.cond = threading.Condition()
        self.active = False  # fast path read by the tracer on every call/line
        self.mode = "run"    # run | pause | step_into | step_over | step_out
        self.step_thread = None
        self.step_depth = 0
        self.call_breaks: set[str] = set()
        self.line_breaks: set[tuple[str, int]] = set()
        self.intercepts: set[str] = set()
        self.paused: dict | None = None
        self.version = 0
        self.closed = False
        self._decision = None
        self._seq = 0
        self._norm: dict[str, str] = {}
        self._tl = threading.local()

    def _refresh(self):
        self.active = not self.closed and (self.mode != "run" or bool(self.call_breaks) or bool(self.line_breaks)
                                           or self.paused is not None)

    # ---------------------------------------------------------------- from the viewer
    def configure(self, call_breaks=None, line_breaks=None, intercepts=None):
        with self.cond:
            if call_breaks is not None:
                self.call_breaks = set(call_breaks)
            if line_breaks is not None:
                self.line_breaks = {(os.path.normcase(f), int(l)) for f, l in line_breaks}
            if intercepts is not None:
                self.intercepts = {k for k in intercepts if k in INTERCEPTS}
            self.version += 1
            self._refresh()

    def command(self, action: str, edits: dict | None = None) -> str | None:
        """Returns an error message, or None."""
        with self.cond:
            if self.paused is None:
                if action == "pause":
                    self.mode = "pause"
                elif action == "continue":
                    self.mode = "run"
                else:
                    return "The program isn't paused."
            else:
                if action == "drop" and self.paused["kind"] != "intercept":
                    return "Only intercepted operations can be dropped."
                if edits and self.paused["kind"] != "call":
                    return "Values can only be edited when paused on a function call."
                if action not in ("continue", "forward", "drop", *STEP_ACTIONS):
                    return f"Unknown action {action!r}."
                self._decision = {"action": "continue" if action in ("forward", "drop") else action,
                                  "drop": action == "drop", "edits": edits or {}}
            self.version += 1
            self._refresh()
            self.cond.notify_all()
        return None

    def config(self) -> dict:
        return {"call_breaks": sorted(self.call_breaks), "line_breaks": sorted([f, l] for f, l in self.line_breaks),
                "intercepts": sorted(self.intercepts), "mode": self.mode}

    def shutdown(self):
        """Program finished: release anything still waiting and stop pausing."""
        with self.cond:
            self.closed = True
            if self.paused is not None and self._decision is None:
                self._decision = {"action": "continue", "drop": False, "edits": {}}
            self.mode = "run"
            self.version += 1
            self._refresh()
            self.cond.notify_all()

    # ---------------------------------------------------------------- from the tracer
    def _hold(self, me):
        """Another thread is paused: wait here so this one doesn't run on underneath it."""
        with self.cond:
            while self.paused is not None and self.paused["thread"] != me and not self.closed:
                self.cond.wait(0.25)

    def on_call(self, frame, rec):
        me = threading.get_ident()
        if self.paused is not None and self.paused["thread"] != me:
            self._hold(me)
        if rec["kind"] in ("python", "generator") or rec["kind"] == "library":
            if graph.function_key(rec) in self.call_breaks:
                return self.pause("breakpoint", "call", frame, rec)
        if self.mode == "pause" or (self.mode == "step_into" and self.step_thread == me):
            return self.pause("paused" if self.mode == "pause" else "step", "call", frame, rec)

    def on_line(self, frame, rec, line):
        me = threading.get_ident()
        if self.paused is not None and self.paused["thread"] != me:
            self._hold(me)
        reason = None
        if self.line_breaks:
            fn = frame.f_code.co_filename
            norm = self._norm.get(fn) or self._norm.setdefault(fn, os.path.normcase(fn))
            if (norm, line) in self.line_breaks:
                reason = "breakpoint"
        if reason is None:
            if self.mode == "pause":
                reason = "paused"
            elif self.step_thread == me and self.mode in STEP_ACTIONS:
                depth = len(self.tracer._stack())
                if (self.mode == "step_into" or (self.mode == "step_over" and depth <= self.step_depth)
                        or (self.mode == "step_out" and depth < self.step_depth)):
                    reason = "step"
        if reason:
            self.pause(reason, "line", frame, rec, line=line)

    # ---------------------------------------------------------------- from the monitor
    def intercept(self, entry: dict, frame) -> dict | None:
        rules = self.intercepts
        kind = entry["kind"]
        hit = None
        if kind == "process" and "process" in rules:
            hit = "process"
        elif kind == "network" and "network" in rules:
            now = time.perf_counter()
            if entry["event"] == "socket.connect" and getattr(self._tl, "url_ok_until", 0) > now:
                return None  # the connection behind a URL you already forwarded
            hit = "network"
        elif kind == "database" and "sql" in rules:
            hit = "sql"
        elif kind == "code" and "code" in rules:
            hit = "code"
        elif kind in ("file", "delete") and entry.get("sensitive") and "sensitive" in rules:
            hit = "sensitive"
        elif kind == "delete" and "delete" in rules:
            hit = "delete"
        elif kind == "file" and entry.get("write") and "file_write" in rules:
            hit = "file_write"
        if hit is None or self.closed:
            return None
        stack = self.tracer._stack()
        rec = self.tracer.calls[stack[-1]] if stack else None
        op = {k: entry.get(k) for k in ("kind", "op", "target", "event")}
        op["rule"] = hit
        d = self.pause("intercept", "intercept", frame, rec, line=frame.f_lineno if frame else None, op=op)
        if entry["event"] == "urllib.Request" and not d.get("drop"):
            self._tl.url_ok_until = time.perf_counter() + 5
        return d

    # ---------------------------------------------------------------- pausing
    def _locals(self, frame) -> dict:
        if frame is None:
            return {}
        try:
            items = list(frame.f_locals.items())
        except Exception:
            return {}
        out = {}
        for k, v in items:
            if k.startswith("__") or type(v).__name__ in ("module", "function", "type", "builtin_function_or_method"):
                continue
            out[k] = safe_repr(v)
            if len(out) >= 60:
                break
        return out

    def pause(self, reason, kind, frame, rec, line=None, op=None) -> dict:
        me = threading.get_ident()
        t_start = time.perf_counter_ns()
        code = frame.f_code if frame is not None else None
        args = []
        if kind == "call" and code is not None:
            args = list(code.co_varnames[:code.co_argcount + code.co_kwonlyargcount])
        with self.cond:
            while self.paused is not None and self.paused["thread"] != me and not self.closed:
                self.cond.wait(0.25)
            if self.closed:
                return {"action": "continue", "drop": False, "edits": {}}
            self._seq += 1
            self.paused = {
                "id": self._seq, "reason": reason, "kind": kind, "thread": me,
                "call": rec["id"] if rec else None,
                "file": code.co_filename if code else None,
                # a frame that hasn't started yet reports line 0; show where the function begins
                "line": line or (frame.f_lineno or code.co_firstlineno if frame is not None else None),
                "func": _qualname(code) if code else None,
                "locals": self._locals(frame), "editable": args, "op": op, "t": self.tracer._now(),
            }
            self.mode = "run"
            self._decision = None
            self.version += 1
            self._refresh()
            self.cond.notify_all()
            where = f"{os.path.basename(self.paused['file'] or '?')}:{self.paused['line']}"
            what = f"intercepted {op['kind']} {op['op']}" if op else reason
            _say(f"paused ({what}) at {where} in {self.paused['func']}. Continue in the browser, or Ctrl+C to stop.")
            while self._decision is None:
                self.cond.wait(0.25)  # short waits keep Ctrl+C working on Windows
            d = self._decision
            self._decision = None
            self.paused = None
            if d["action"] in STEP_ACTIONS and not self.closed:
                self.mode, self.step_thread, self.step_depth = d["action"], me, len(self.tracer._stack())
            else:
                self.mode = "run"
            self.version += 1
            self._refresh()
            self.cond.notify_all()
        self.tracer.t0 += time.perf_counter_ns() - t_start  # paused time doesn't count
        if d["edits"] and kind == "call" and frame is not None:
            self._apply_edits(frame, rec, d["edits"])
        return d

    @staticmethod
    def _apply_edits(frame, rec, edits: dict):
        loc = frame.f_locals  # read ONCE: every read re-syncs from the frame and would drop earlier edits
        edited = rec.setdefault("edited", {})
        for name, value in edits.items():
            old = loc.get(name)
            loc[name] = value
            edited[name] = {"from": safe_repr(old), "to": safe_repr(value)}
            if rec.get("args") is not None and name in rec["args"]:
                rec["args"][name] = safe_repr(value)


def parse_edits(raw: dict, editable: list[str]) -> tuple[dict, str | None]:
    """Values typed in the viewer are Python literals ('text', 42, [1, 2], {'a': 1}, None)."""
    out = {}
    for name, text in (raw or {}).items():
        if name not in editable:
            return {}, f"{name} isn't an argument of this call."
        try:
            out[name] = ast.literal_eval(text)
        except (ValueError, SyntaxError):
            return {}, (f"{name}: {text!r} isn't a Python literal. Strings need quotes, e.g. 'alice'; "
                        "numbers, lists, dicts, True/False and None work as-is.")
    return out, None


class LiveServer:
    def __init__(self, tracer, ctl: Controller, monitor, meta: dict):
        self.tracer, self.ctl, self.monitor, self.meta = tracer, ctl, monitor, meta
        self.token = secrets.token_urlsafe(18)
        self.final: dict | None = None
        self.final_sent = threading.Event()
        self.connected = threading.Event()
        self._decisions: dict[str, list] = {}
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):  # stderr is the traced program's while it runs
                pass

            def _ok_host(self):
                return self.headers.get("Host") in (f"127.0.0.1:{server.port}", f"localhost:{server.port}")

            def _send(self, code, body: bytes, ctype="application/json"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _json(self, code, obj):
                self._send(code, json.dumps(obj, separators=(",", ":")).encode())

            def do_GET(self):
                url = urlsplit(self.path)
                q = {k: v[0] for k, v in parse_qs(url.query).items()}
                if not self._ok_host():
                    return self._send(403, b"forbidden", "text/plain")
                if url.path == "/":
                    if not secrets.compare_digest(q.get("t", ""), server.token):
                        return self._send(403, b"Open the link printed in the terminal.", "text/plain")
                    return self._send(200, server.page().encode(), "text/html; charset=utf-8")
                if url.path == "/api/poll":
                    if not secrets.compare_digest(self.headers.get("X-Traceflow-Token", ""), server.token):
                        return self._send(403, b"forbidden", "text/plain")
                    server.connected.set()
                    return self._json(200, server.poll(q))
                self._send(404, b"not found", "text/plain")

            def do_POST(self):
                if (not self._ok_host() or self.headers.get("Content-Type") != "application/json"
                        or not secrets.compare_digest(self.headers.get("X-Traceflow-Token", ""), server.token)):
                    return self._send(403, b"forbidden", "text/plain")
                try:
                    body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                except ValueError:
                    return self._json(400, {"error": "Bad JSON."})
                path = urlsplit(self.path).path
                if path == "/api/config":
                    server.ctl.configure(body.get("call_breaks"), body.get("line_breaks"), body.get("intercepts"))
                    return self._json(200, {"ok": True, "config": server.ctl.config()})
                if path == "/api/control":
                    edits, err = {}, None
                    if body.get("edits"):
                        paused = server.ctl.paused
                        edits, err = parse_edits(body["edits"], paused["editable"] if paused else [])
                    err = err or server.ctl.command(body.get("action", ""), edits)
                    return self._json(400 if err else 200, {"error": err} if err else {"ok": True})
                self._send(404, b"not found", "text/plain")

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.handle_error = lambda request, addr: None
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/?t={self.token}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="traceflow-live", daemon=True)

    def start(self):
        self.thread.start()  # before tracing starts, so this thread is never traced

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def page(self) -> str:
        initial = {"meta": {**self.meta, "duration_ns": 0, "call_count": 0}, "calls": [], "events": [], "sources": {},
                   "functions": [], "edges": [],
                   "security": {"findings": [], "activity": [], "packages": [], "notes": [],
                                "summary": {"high": 0, "medium": 0, "low": 0, "info": 0}, "redacted": 0}}
        return render.to_html(initial, live={"intercepts": INTERCEPTS})

    # ---------------------------------------------------------------- polling
    def _branches(self, rec_lines: dict, source: str | None) -> list:
        if not source:
            return []
        dec = self._decisions.get(source)
        if dec is None:
            src = self.tracer.sources.get(source)
            dec = self._decisions[source] = graph.static_decisions(src) if src else []
        return graph.evaluate_branches(dec, rec_lines)

    def _serialize(self, rec: dict) -> dict:
        r = {k: v for k, v in dict(rec).items() if not k.startswith("_")}  # dict() copies are atomic under the GIL
        r["lines"] = {str(k): v for k, v in dict(rec["lines"]).items()}
        arcs = rec["arcs"]
        r["arcs"] = [[a, b, n] for (a, b), n in dict(arcs).items()] if isinstance(arcs, dict) else list(arcs)
        r["children"] = list(rec["children"])
        r["handled"] = list(rec["handled"])
        if rec.get("args") is not None:
            r["args"] = dict(rec["args"])
        if rec.get("edited"):
            r["edited"] = dict(rec["edited"])
        r["branches"] = self._branches(r["lines"], r.get("source"))
        return r

    def poll(self, q: dict) -> dict:
        if self.final is not None:
            self.final_sent.set()
            return {"final": self.final, "state": {"status": "finished", "config": self.ctl.config()}}
        tr, ctl = self.tracer, self.ctl
        num = lambda k: max(int(q.get(k, 0) or 0), 0)
        c0, x0, e0, a0, s0 = num("c"), num("x"), num("e"), num("a"), num("s")
        # Read the cursors first, then the data; anything newer goes out on the next poll. Events,
        # activity and closings are counted before calls, so everything sent refers to calls that are
        # also sent; sources after calls, because a call's source is registered before the call.
        e1, x1 = len(tr.events), len(tr.closed_log)
        a1 = len(self.monitor.activity) if self.monitor else 0
        n = len(tr.calls)
        src_keys = list(tr.sources)
        ids = set(range(min(c0, n), n)) | set(tr.closed_log[x0:x1]) | set(tr.open_ids)
        calls = [self._serialize(tr.calls[i]) for i in sorted(ids) if i < n]
        keep = ("stdout", "stderr", "stdin", "catch", "raise")
        events = [dict(e) for e in tr.events[e0:e1] if e["type"] in keep]
        activity = [{k: v for k, v in dict(a).items() if k != "seq"} for a in self.monitor.activity[a0:a1]] if self.monitor else []
        sources = {k: tr.sources[k] for k in src_keys[s0:]}
        paused = ctl.paused
        return {
            "calls": calls, "events": events, "activity": activity, "sources": sources,
            "cursors": {"c": n, "x": x1, "e": e1, "a": a1, "s": len(src_keys)},
            "state": {"status": "paused" if paused else "running", "pause": dict(paused) if paused else None,
                      "now": paused["t"] if paused else tr._now(), "version": ctl.version, "config": ctl.config(),
                      "truncated": tr.truncated},
        }
