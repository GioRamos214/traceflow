"""Diagram renderer: embeds the built graph into a single self-contained HTML file."""

import json
import os

_TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "viewer.html")


def _embed(obj) -> str:
    return json.dumps(obj, separators=(",", ":")).replace("</", "<\\/")


def to_html(data: dict, live: dict | None = None) -> str:
    """`live` turns the page into the live viewer (served by live.LiveServer, which it polls)."""
    with open(_TEMPLATE, encoding="utf-8") as f:
        tpl = f.read()
    return tpl.replace("/*__TRACE_DATA__*/null", _embed(data)).replace("/*__LIVE__*/null", _embed(live))


def write_html(data: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_html(data))
