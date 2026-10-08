"""Known-vulnerability lookup for the third-party packages a run actually imported.

Uses the public OSV.dev API (https://osv.dev). Only package names and versions are
sent. Unlike a requirements-file audit, the list comes from the run itself, so each
package is marked as called directly by your code or only imported.
"""

from __future__ import annotations

import json
import os
import sys
import sysconfig
import urllib.request
from importlib import metadata

from .tracer import _under

OSV_API = "https://api.osv.dev/v1"
MAX_DETAILS = 60


def _site_dirs() -> list[str]:
    dirs = {os.path.abspath(p) for k in ("purelib", "platlib") if (p := sysconfig.get_paths().get(k))}
    dirs |= {os.path.abspath(p) for p in sys.path if p and ("site-packages" in p or "dist-packages" in p)}
    return sorted(dirs)


def imported_distributions(called_modules) -> list[dict]:
    """Installed distributions with at least one module imported in this process."""
    site = _site_dirs()
    tops = set()
    for name, mod in list(sys.modules.items()):
        f = getattr(mod, "__file__", None)
        if f and any(_under(os.path.abspath(f), d) for d in site):
            tops.add(name.split(".")[0])
    called = {m.split(".")[0] for m in called_modules if m}
    by_dist: dict[str, dict] = {}
    dist_map = metadata.packages_distributions()
    for top in sorted(tops):
        for dist in dist_map.get(top, []):
            try:
                version = metadata.version(dist)
            except metadata.PackageNotFoundError:
                continue
            p = by_dist.setdefault(dist.lower(), {"name": dist, "version": version, "modules": [], "called": False, "vulns": []})
            p["modules"].append(top)
            p["called"] = p["called"] or top in called
    return sorted(by_dist.values(), key=lambda p: p["name"].lower())


def _request(url: str, body: dict | None = None, timeout: float = 10.0) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def _fixed_versions(vuln: dict, package: str) -> list[str]:
    out = []
    for aff in vuln.get("affected", []):
        if (aff.get("package") or {}).get("name", "").lower() != package.lower():
            continue
        for rng in aff.get("ranges", []):
            out += [ev["fixed"] for ev in rng.get("events", []) if "fixed" in ev]
    return out


def check(packages: list[dict], timeout: float = 10.0, ecosystem: str = "PyPI") -> None:
    """Fill in p["vulns"] for each package. Raises on network errors."""
    packages = [p for p in packages if p.get("version") and p["version"] != "unknown"]
    if not packages:
        return
    batch = _request(f"{OSV_API}/querybatch", {"queries": [
        {"package": {"name": p["name"], "ecosystem": ecosystem}, "version": p["version"]} for p in packages]}, timeout)
    details: dict[str, dict] = {}
    for p, result in zip(packages, batch.get("results", [])):
        p.setdefault("vulns", [])
        for v in result.get("vulns") or []:
            vid = v["id"]
            if vid not in details and len(details) < MAX_DETAILS:
                try:
                    details[vid] = _request(f"{OSV_API}/vulns/{vid}", timeout=timeout)
                except OSError:
                    details[vid] = {"id": vid}
            d = details.get(vid, {"id": vid})
            p["vulns"].append({
                "id": vid,
                "summary": d.get("summary") or (d.get("details") or "")[:200],
                "severity": (d.get("database_specific") or {}).get("severity"),
                "aliases": d.get("aliases", []),
                "fixed": _fixed_versions(d, p["name"]),
            })
