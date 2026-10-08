"""Graph builder: turns the raw event store into things a human can read.

* call tree       – every invocation, parent -> children (already in the trace)
* function graph  – unique functions as nodes, caller->callee edges with counts/time
* branches        – for each invocation, which side of every if/elif/else,
                    loop, try/except and match/case actually ran, derived by
                    matching the function's AST against that call's line hits.
"""

from __future__ import annotations

import ast
import textwrap

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _first_line(stmts):
    return stmts[0].lineno if stmts else None


def _walk_scope(node):
    """Yield nodes inside this code object's scope, not descending into nested defs."""
    for child in ast.iter_child_nodes(node):
        yield child
        if not isinstance(child, _SCOPES):
            yield from _walk_scope(child)


def static_decisions(src: dict) -> list[dict]:
    """Find decision points in one code object's source. Line numbers are absolute."""
    lines = src.get("lines") or []
    if not lines:
        return []
    off = src["start"] - 1
    try:
        tree = ast.parse(textwrap.dedent("\n".join(lines)))
    except SyntaxError:
        return []
    root = tree
    if src["name"] != "<module>":
        root = next((n for n in tree.body if isinstance(n, _SCOPES)), tree)

    text = lambda ln: lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
    A = lambda ln: None if ln is None else ln + off
    out = []
    for n in _walk_scope(root):
        if isinstance(n, ast.If):
            is_elif = text(n.lineno).startswith("elif")
            else_is_elif = len(n.orelse) == 1 and isinstance(n.orelse[0], ast.If) and text(n.orelse[0].lineno).startswith("elif")
            out.append({"kind": "elif" if is_elif else "if", "line": A(n.lineno), "text": text(n.lineno),
                        "body": A(_first_line(n.body)), "orelse": A(_first_line(n.orelse)),
                        "orelse_kind": "elif" if else_is_elif else ("else" if n.orelse else None)})
        elif isinstance(n, (ast.For, ast.AsyncFor, ast.While)):
            out.append({"kind": "while" if isinstance(n, ast.While) else "for", "line": A(n.lineno),
                        "text": text(n.lineno), "body": A(_first_line(n.body)), "orelse": A(_first_line(n.orelse))})
        elif isinstance(n, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            out.append({"kind": "try", "line": A(n.lineno), "text": text(n.lineno), "body": A(_first_line(n.body)),
                        "handlers": [{"text": text(h.lineno), "line": A(_first_line(h.body))} for h in n.handlers],
                        "orelse": A(_first_line(n.orelse)), "final": A(_first_line(n.finalbody))})
        elif hasattr(ast, "Match") and isinstance(n, ast.Match):
            out.append({"kind": "match", "line": A(n.lineno), "text": text(n.lineno),
                        "cases": [{"text": text(c.pattern.lineno), "line": A(_first_line(c.body))} for c in n.cases]})
    out.sort(key=lambda d: d["line"])
    return out


def evaluate_branches(decisions: list[dict], hits: dict[str, int]) -> list[dict]:
    h = lambda ln: hits.get(str(ln), 0) if ln is not None else 0
    res = []
    for d in decisions:
        ev = h(d["line"])
        r = {"kind": d["kind"], "line": d["line"], "text": d["text"], "reached": ev > 0, "outcome": "not reached", "taken": []}
        if ev == 0 and d["kind"] != "try":
            res.append(r)
            continue
        k = d["kind"]
        if k in ("if", "elif"):
            if d["body"] == d["line"]:
                r["outcome"] = f"evaluated ×{ev}"
            else:
                t = h(d["body"])
                f = max(ev - t, 0)
                other = d.get("orelse_kind")
                f_label = f"False → {other}" if other else "False (skipped)"
                if t and f:
                    r["outcome"] = f"True ×{t}, {f_label} ×{f}"
                elif t:
                    r["outcome"] = "True" if t == 1 else f"True ×{t}"
                else:
                    r["outcome"] = f_label if f == 1 else f"{f_label} ×{f}"
                r["taken"] = (["true"] if t else []) + (["false"] if f else [])
        elif k in ("for", "while"):
            b = h(d["body"])
            r["outcome"] = f"{b} iteration{'s' if b != 1 else ''}" if b else "body never ran"
            if d.get("orelse") and h(d["orelse"]):
                r["outcome"] += ", else ran"
        elif k == "try":
            if not h(d["body"]) and not ev:
                res.append(r)
                continue
            r["reached"] = True
            ran = [hd["text"] for hd in d["handlers"] if h(hd["line"])]
            parts = [f"handler ran: {', '.join(ran)}"] if ran else ["no exception caught"]
            if d.get("orelse") and h(d["orelse"]):
                parts.append("else ran")
            if d.get("final") and h(d["final"]):
                parts.append("finally ran")
            r["outcome"] = "; ".join(parts)
            r["taken"] = ["except"] if ran else ["ok"]
        elif k == "match":
            ran = [c["text"] for c in d["cases"] if h(c["line"])]
            r["outcome"] = f"matched {', '.join(ran)}" if ran else "no case matched"
        res.append(r)
    return res


def function_key(c: dict) -> str:
    if c["kind"] == "builtin":
        return f"builtin:{c['qualname']}"
    return f"{c['kind']}:{c['file']}:{c['def_line']}:{c['qualname']}"


def build(trace: dict) -> dict:
    calls = trace["calls"]
    decisions = {k: static_decisions(s) for k, s in trace["sources"].items()}

    for c in calls:
        c["dur"] = (c["end"] or 0) - c["start"]
    for c in calls:
        c["self"] = c["dur"] - sum(calls[ch]["dur"] for ch in c["children"])
        c["fn"] = function_key(c)
        c["branches"] = evaluate_branches(decisions.get(c["source"], []), c["lines"]) if c["source"] else []

    functions: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}
    for c in calls:
        f = functions.setdefault(c["fn"], {
            "key": c["fn"], "kind": c["kind"], "name": c["name"], "qualname": c["qualname"], "file": c["file"],
            "def_line": c["def_line"], "calls": [], "total": 0, "self": 0, "depth": c["depth"], "raised": 0})
        f["calls"].append(c["id"])
        f["total"] += c["dur"]
        f["self"] += c["self"]
        f["depth"] = min(f["depth"], c["depth"])
        f["raised"] += c["status"] == "raised"
        if c["parent"] is not None:
            p = calls[c["parent"]]
            e = edges.setdefault((p["fn"], c["fn"]), {"from": p["fn"], "to": c["fn"], "count": 0, "total": 0})
            e["count"] += 1
            e["total"] += c["dur"]

    return {
        "meta": trace["meta"],
        "calls": calls,
        "sources": trace["sources"],
        "events": [e for e in trace["events"] if e["type"] in ("stdout", "stderr", "stdin", "catch", "raise")],
        "functions": list(functions.values()),
        "edges": list(edges.values()),
        "security": trace.get("security"),
    }
