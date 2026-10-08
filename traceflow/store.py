"""Execution event store: ordered events + call records, as JSON or SQLite."""

from __future__ import annotations

import json
import os
import sqlite3


def trace_to_dict(tracer, meta: dict) -> dict:
    return {
        "format": "traceflow-trace/1",
        "meta": {**meta, "duration_ns": tracer.t_end, "truncated": tracer.truncated,
                 "call_count": len(tracer.calls)},
        "calls": tracer.calls,
        "events": tracer.events,
        "sources": tracer.sources,
    }


def save_json(trace: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(trace, f, separators=(",", ":"))


def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


SCHEMA = """
CREATE TABLE meta    (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE calls   (id INTEGER PRIMARY KEY, parent INTEGER, depth INTEGER, kind TEXT, thread INTEGER,
                      name TEXT, qualname TEXT, module TEXT, file TEXT, def_line INTEGER, source TEXT,
                      caller_file TEXT, caller_line INTEGER, caller_name TEXT,
                      start_ns INTEGER, end_ns INTEGER, status TEXT,
                      args TEXT, return_value TEXT, exception TEXT, handled TEXT);
CREATE TABLE events  (seq INTEGER PRIMARY KEY, t_ns INTEGER, type TEXT, call_id INTEGER, data TEXT);
CREATE TABLE line_hits (call_id INTEGER, line INTEGER, hits INTEGER);
CREATE TABLE arcs    (call_id INTEGER, from_line INTEGER, to_line INTEGER, hits INTEGER);
CREATE TABLE sources (key TEXT PRIMARY KEY, file TEXT, start INTEGER, name TEXT, code TEXT);
CREATE INDEX calls_parent ON calls(parent);
CREATE INDEX events_call ON events(call_id);
"""

SECURITY_SCHEMA = """
CREATE TABLE findings (rule TEXT, owasp TEXT, category TEXT, severity TEXT, title TEXT, detail TEXT, fix TEXT,
                       call_id INTEGER, file TEXT, line INTEGER, evidence TEXT);
CREATE TABLE activity (t_ns INTEGER, kind TEXT, op TEXT, target TEXT, sensitive INTEGER,
                       call_id INTEGER, file TEXT, line INTEGER);
CREATE TABLE packages (name TEXT, version TEXT, called INTEGER, vulns TEXT);
"""


def save_sqlite(trace: dict, path: str):
    if os.path.exists(path):
        os.remove(path)
    db = sqlite3.connect(path)
    db.executescript(SCHEMA)
    db.executemany("INSERT INTO meta VALUES (?,?)", [(k, json.dumps(v)) for k, v in trace["meta"].items()])
    j = lambda v: None if v is None else json.dumps(v)
    db.executemany(
        "INSERT INTO calls VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(c["id"], c["parent"], c["depth"], c["kind"], c["thread"], c["name"], c["qualname"], c["module"],
          c["file"], c["def_line"], c["source"], c["caller_file"], c["caller_line"], c["caller_name"],
          c["start"], c["end"], c["status"], j(c["args"]), c["return"], j(c["exception"]), j(c["handled"]))
         for c in trace["calls"]])
    db.executemany(
        "INSERT INTO events VALUES (?,?,?,?,?)",
        [(e["seq"], e["t"], e["type"], e["call"],
          j({k: v for k, v in e.items() if k not in ("seq", "t", "type", "call")}) or None)
         for e in trace["events"]])
    db.executemany("INSERT INTO line_hits VALUES (?,?,?)",
                   [(c["id"], int(l), n) for c in trace["calls"] for l, n in c["lines"].items()])
    db.executemany("INSERT INTO arcs VALUES (?,?,?,?)",
                   [(c["id"], a, b, n) for c in trace["calls"] for a, b, n in c["arcs"]])
    db.executemany("INSERT INTO sources VALUES (?,?,?,?,?)",
                   [(k, s["file"], s["start"], s["name"], "\n".join(s["lines"])) for k, s in trace["sources"].items()])
    sec = trace.get("security")
    if sec:
        db.executescript(SECURITY_SCHEMA)
        db.executemany("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       [(f["rule"], f["owasp"], f["category"], f["severity"], f["title"], f["detail"], f["fix"],
                         f["call"], f["file"], f["line"], f["evidence"]) for f in sec["findings"]])
        db.executemany("INSERT INTO activity VALUES (?,?,?,?,?,?,?,?)",
                       [(a["t"], a["kind"], a["op"], a["target"], int(a.get("sensitive", False)),
                         a.get("call"), a.get("file"), a.get("line")) for a in sec["activity"]])
        db.executemany("INSERT INTO packages VALUES (?,?,?,?)",
                       [(p["name"], p["version"], int(p["called"]), json.dumps(p["vulns"])) for p in sec["packages"]])
    db.commit()
    db.close()
