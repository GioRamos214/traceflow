"""Runtime tracing engine.

Two CPython hooks are combined:

* ``sys.settrace``   -> Python-level frames: call / line / return / exception.
                        Line events give us per-call line hit counts, which is
                        how the graph builder reconstructs which branch ran.
* ``sys.setprofile`` -> C-level calls (``print``, ``input``, ``time.sleep`` ...)
                        that settrace never sees.

Only "user" code (files under the include paths, outside the stdlib /
site-packages) is traced line-by-line. Calls from user code *into* a library
are recorded as a single opaque "library" node so you can still see that
``main()`` called ``json.load`` without drowning in stdlib internals.
"""

from __future__ import annotations

import inspect
import io
import linecache
import os
import reprlib
import sys
import sysconfig
import threading
import time

_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
CO_GENERATOR = inspect.CO_GENERATOR | inspect.CO_COROUTINE | inspect.CO_ASYNC_GENERATOR

_repr = reprlib.Repr()
_repr.maxstring = 120
_repr.maxother = 120
_repr.maxlist = _repr.maxtuple = _repr.maxset = _repr.maxdict = 8
_repr.maxlevel = 3


def safe_repr(value) -> str:
    try:
        return _repr.repr(value)
    except Exception:  # user __repr__ blew up (e.g. object half-initialised)
        return f"<{type(value).__name__} (repr failed)>"


def _under(path: str, root: str) -> bool:
    path, root = os.path.normcase(path), os.path.normcase(root)  # Windows: d:\x == D:\X
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _qualname(code) -> str:
    return getattr(code, "co_qualname", code.co_name)  # co_qualname is 3.11+


class _TeeStream(io.TextIOBase):
    """Wraps stdout/stderr/stdin and attributes each write/read to the call
    that was running at that moment."""

    def __init__(self, inner, tracer: "Tracer", kind: str):
        self._inner, self._tracer, self._kind = inner, tracer, kind

    # --- output
    def write(self, s):
        if s:
            self._tracer._record_io(self._kind, s)
        return self._inner.write(s)

    def flush(self):
        return self._inner.flush()

    # --- input
    def readline(self, *a):
        line = self._inner.readline(*a)
        self._tracer._record_io(self._kind, line if line else "<EOF>")
        return line

    def read(self, *a):
        data = self._inner.read(*a)
        self._tracer._record_io(self._kind, data)
        return data

    def __getattr__(self, name):  # encoding, fileno, isatty, buffer ...
        return getattr(self._inner, name)


class Tracer:
    def __init__(
        self,
        include: list[str] | None = None,
        builtins: str = "module",  # "none" | "module" (print, input, time.sleep...) | "all" (incl. methods)
        library_calls: bool = True,
        capture_values: bool = True,
        capture_io: bool = True,
        max_calls: int = 250_000,
    ):
        self.include = [os.path.abspath(p) for p in (include or [])]
        self.excludes = self._default_excludes()
        self.builtins_mode = builtins
        self.library_calls = library_calls
        self.capture_values = capture_values
        self.capture_io = capture_io
        self.max_calls = max_calls

        self.calls: list[dict] = []     # call records, index == id
        self.events: list[dict] = []    # ordered event log
        self.sources: dict[str, dict] = {}
        self.truncated = False
        self.t0 = 0
        self.t_end = 0
        # Live mode: which records are still running / when each one finished, so a viewer polling
        # from another thread can send only what changed. `ctl` (live.Controller) pauses the program.
        self.open_ids: set[int] = set()
        self.closed_log: list[int] = []
        self.ctl = None

        self._file_ok: dict[str, bool] = {}
        self._frame_call: dict[int, int] = {}   # id(frame) -> call id
        self._local = threading.local()
        self._lock = threading.Lock()
        self._saved_streams = None

    # ------------------------------------------------------------------ setup
    @staticmethod
    def _default_excludes() -> list[str]:
        paths = {_PKG_DIR}
        for key in ("stdlib", "platstdlib", "purelib", "platlib"):
            p = sysconfig.get_paths().get(key)
            if p:
                paths.add(os.path.abspath(p))
        for p in sys.path:
            if p and ("site-packages" in p or "dist-packages" in p):
                paths.add(os.path.abspath(p))
        return sorted(paths)

    def _is_user_file(self, filename: str) -> bool:
        ok = self._file_ok.get(filename)
        if ok is None:
            if not filename or filename.startswith("<"):
                ok = False
            else:
                p = os.path.abspath(filename)
                ok = not any(_under(p, e) for e in self.excludes) and (
                    not self.include or any(_under(p, i) for i in self.include)
                )
            self._file_ok[filename] = ok
        return ok

    def start(self):
        self.t0 = time.perf_counter_ns()
        if self.capture_io:
            self._saved_streams = (sys.stdout, sys.stderr, sys.stdin)
            sys.stdout = _TeeStream(sys.stdout, self, "stdout")
            sys.stderr = _TeeStream(sys.stderr, self, "stderr")
            sys.stdin = _TeeStream(sys.stdin, self, "stdin")
        threading.settrace(self._global_trace)
        threading.setprofile(self._profile)
        sys.setprofile(self._profile)
        sys.settrace(self._global_trace)

    def stop(self):
        sys.settrace(None)
        sys.setprofile(None)
        threading.settrace(None)  # type: ignore[arg-type]
        threading.setprofile(None)  # type: ignore[arg-type]
        self.t_end = self._now()
        if self._saved_streams:
            sys.stdout, sys.stderr, sys.stdin = self._saved_streams
            self._saved_streams = None
        for rec in self.calls:  # anything still open (threads, hard exit)
            if rec["end"] is None:
                rec["end"] = self.t_end
                rec["status"] = "unfinished"
            rec.pop("_pending_exc", None)
            rec.pop("_last_line", None)
            rec["lines"] = {str(k): v for k, v in rec["lines"].items()}
            rec["arcs"] = [[a, b, n] for (a, b), n in rec["arcs"].items()]

    # ---------------------------------------------------------------- helpers
    def _now(self) -> int:
        return time.perf_counter_ns() - self.t0

    def _stack(self) -> list[int]:
        s = getattr(self._local, "stack", None)
        if s is None:
            s = self._local.stack = []
        return s

    def _event(self, etype: str, call_id, **extra):
        ev = {"seq": len(self.events), "t": self._now(), "type": etype, "call": call_id}
        ev.update(extra)
        self.events.append(ev)

    def _record_io(self, kind: str, text: str):
        stack = self._stack()
        cid = stack[-1] if stack else None
        self._event(kind, cid, text=text)

    def _source_key(self, code) -> str:
        key = f"{code.co_filename}:{code.co_firstlineno}:{_qualname(code)}"
        if key not in self.sources:
            try:
                if code.co_name == "<module>":  # getsourcelines only returns the first block here
                    lines, start = linecache.getlines(code.co_filename), 1
                else:
                    lines, start = inspect.getsourcelines(code)
                    start = max(start, 1)
            except (OSError, TypeError):
                lines, start = [], code.co_firstlineno
            self.sources[key] = {
                "file": code.co_filename,
                "start": start,
                "name": _qualname(code),
                "lines": [l.rstrip("\n") for l in lines],
            }
        return key

    def _args(self, frame) -> dict | None:
        if not self.capture_values:
            return None
        try:
            info = inspect.getargvalues(frame)
        except Exception:
            return None
        out = {}
        for name in info.args:
            out[name] = safe_repr(info.locals.get(name))
        if info.varargs:
            out["*" + info.varargs] = safe_repr(info.locals.get(info.varargs))
        if info.keywords:
            out["**" + info.keywords] = safe_repr(info.locals.get(info.keywords))
        return out

    def _new_record(self, kind, name, qualname, file, def_line, frame_for_caller, source=None, module=None):
        stack = self._stack()
        parent = stack[-1] if stack else None
        cid = len(self.calls)
        caller = frame_for_caller
        rec = {
            "id": cid,
            "parent": parent,
            "depth": (self.calls[parent]["depth"] + 1) if parent is not None else 0,
            "kind": kind,  # python | generator | library | builtin
            "thread": threading.get_ident(),
            "name": name,
            "qualname": qualname,
            "module": module,
            "file": file,
            "def_line": def_line,
            "source": source,
            "caller_file": caller.f_code.co_filename if caller else None,
            "caller_line": caller.f_lineno if caller else None,
            "caller_name": _qualname(caller.f_code) if caller else None,
            "start": self._now(),
            "end": None,
            "status": "running",
            "args": None,
            "return": None,
            "exception": None,
            "handled": [],  # exceptions raised inside and caught in this frame
            "children": [],
            "lines": {},
            "arcs": {},
            "_pending_exc": None,
            "_last_line": None,
        }
        self.calls.append(rec)
        self.open_ids.add(cid)
        if parent is not None:
            self.calls[parent]["children"].append(cid)
        stack.append(cid)
        self._event("call", cid)
        return rec

    def _close(self, rec, status, value=None, exc=None):
        rec["end"] = self._now()
        rec["status"] = status
        if status == "returned" and self.capture_values:
            rec["return"] = safe_repr(value)
        if exc:
            rec["exception"] = exc
        self.open_ids.discard(rec["id"])
        self.closed_log.append(rec["id"])
        stack = self._stack()
        while stack:  # pop up to and including this record (robust to oddities)
            if stack.pop() == rec["id"]:
                break
        self._event("return" if status != "raised" else "raise", rec["id"])

    # ------------------------------------------------------------- settrace
    def _global_trace(self, frame, event, arg):
        if event != "call":
            return None
        code = frame.f_code
        if len(self.calls) >= self.max_calls:
            self.truncated = True
            return None

        if self._is_user_file(code.co_filename):
            kind = "generator" if code.co_flags & CO_GENERATOR else "python"
            rec = self._new_record(
                kind, code.co_name, _qualname(code), code.co_filename, code.co_firstlineno,
                frame.f_back, source=self._source_key(code),
            )
            rec["args"] = self._args(frame)
            self._frame_call[id(frame)] = rec["id"]
            if self.ctl is not None and self.ctl.active:
                self.ctl.on_call(frame, rec)
            return self._make_local(rec, lines=True)

        # A library function called *directly* from traced user code -> one opaque node.
        if (self.library_calls and not code.co_filename.startswith("<")
                and not _under(os.path.abspath(code.co_filename), _PKG_DIR)):
            parent_cid = self._frame_call.get(id(frame.f_back)) if frame.f_back else None
            if parent_cid is not None and self.calls[parent_cid]["kind"] in ("python", "generator"):
                module = frame.f_globals.get("__name__")
                rec = self._new_record(
                    "library", code.co_name, f"{module}.{_qualname(code)}", code.co_filename,
                    code.co_firstlineno, frame.f_back, module=module,
                )
                rec["args"] = self._args(frame)
                self._frame_call[id(frame)] = rec["id"]
                if self.ctl is not None and self.ctl.active:
                    self.ctl.on_call(frame, rec)  # lets you pause on, and edit, e.g. urlopen(url)
                # Line events stay on for this one frame (not its callees): they're how we tell an
                # exception the library caught itself (e.g. Path.exists) from one that escaped.
                return self._make_local(rec, lines=False)
        return None

    def _make_local(self, rec, lines: bool):
        calls = self.calls
        frame_call = self._frame_call
        ctl = self.ctl

        def local(frame, event, arg):
            if event == "line":
                ln = frame.f_lineno
                pend = rec["_pending_exc"]
                if pend is not None:  # exception was raised, now we're running again -> it was caught
                    pend["caught_at"] = ln
                    rec["handled"].append(pend)
                    rec["_pending_exc"] = None
                    self._event("catch", rec["id"], exc=pend["type"], line=ln)
                if lines:
                    hits = rec["lines"]
                    hits[ln] = hits.get(ln, 0) + 1
                    last = rec["_last_line"]
                    if last is not None:
                        arc = (last, ln)
                        rec["arcs"][arc] = rec["arcs"].get(arc, 0) + 1
                    rec["_last_line"] = ln
                    if ctl is not None and ctl.active:
                        ctl.on_line(frame, rec, ln)
            elif event == "exception":
                etype, evalue, _tb = arg
                info = {"type": getattr(etype, "__name__", str(etype)), "message": safe_repr(str(evalue)), "line": frame.f_lineno}
                rec["_pending_exc"] = info
                # A C call (builtin) that just raised can't tell us *what* it raised; fill it in now.
                if rec["children"]:
                    last = calls[rec["children"][-1]]
                    if last["kind"] == "builtin" and last["status"] == "raised" and last["exception"] is None:
                        last["exception"] = dict(info)
            elif event == "return":
                frame_call.pop(id(frame), None)
                pend = rec["_pending_exc"]
                if pend is not None:
                    self._close(rec, "raised", exc=pend)
                else:
                    self._close(rec, "returned" if rec["kind"] != "generator" else "suspended", value=arg)
            return local

        return local

    # ------------------------------------------------------------ setprofile
    def _profile(self, frame, event, arg):
        if event == "c_call":
            if self.builtins_mode == "none":
                return
            cid = self._frame_call.get(id(frame))
            if cid is None or self.calls[cid]["kind"] not in ("python", "generator"):
                return
            owner = getattr(arg, "__self__", None)
            is_module_fn = owner is None or inspect.ismodule(owner)
            if self.builtins_mode == "module" and not is_module_fn:
                return
            if len(self.calls) >= self.max_calls:
                self.truncated = True
                return
            module = getattr(arg, "__module__", None) or (owner.__name__ if inspect.ismodule(owner) else type(owner).__name__)
            name = getattr(arg, "__name__", repr(arg))
            qual = getattr(arg, "__qualname__", name)
            self._new_record("builtin", name, qual if module in (None, "builtins") else f"{module}.{qual}",
                             None, None, frame, module=module)
        elif event in ("c_return", "c_exception"):
            stack = self._stack()
            if not stack:
                return
            rec = self.calls[stack[-1]]
            if rec["kind"] != "builtin" or rec["end"] is not None:
                return
            if self._frame_call.get(id(frame)) != rec["parent"]:
                return
            self._close(rec, "returned" if event == "c_return" else "raised")
            if event == "c_return":
                rec["return"] = None  # value isn't exposed to profile hooks
