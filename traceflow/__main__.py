"""traceflow command line.

    python -m traceflow run app.py [app args...]           trace a script, write trace + viewer
    python -m traceflow run -m package [app args...]       trace a module, like `python -m package`
    python -m traceflow render trace.json -o viewer.html   re-render a saved trace
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import runpy
import shutil
import subprocess
import sys
import traceback
import webbrowser
from datetime import datetime
from pathlib import Path

from . import graph, live, osv, render, security, store
from .tracer import Tracer, _under


PROJECT_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg", ".git")


def find_project_root(start: str, markers=PROJECT_MARKERS) -> str:
    """Nearest folder at or above `start` with a project marker; else the cwd if
    `start` is inside it; else `start` itself."""
    d = start
    while True:
        if any(os.path.exists(os.path.join(d, m)) for m in markers):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    cwd = os.getcwd()
    return cwd if _under(start, cwd) else start


JS_EXTS = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")


def cmd_run(a):
    if not a.module and a.script and (a.lang in ("js", "node") or
                                      (a.lang == "auto" and os.path.splitext(a.script)[1].lower() in JS_EXTS)):
        return cmd_run_node(a)
    if a.module:
        module, *app_args = a.module
        script = None
        entry_dir = os.getcwd()  # `python -m` resolves the module from the cwd
        base = module
    else:
        if not a.script:
            sys.exit("traceflow run: give a script path or -m module")
        script, app_args = os.path.abspath(a.script), a.args
        entry_dir = os.path.dirname(script)
        base = os.path.splitext(os.path.basename(script))[0]
    root = os.path.abspath(a.root) if a.root else find_project_root(entry_dir)
    include = [os.path.abspath(p) for p in a.include] if a.include else [root]
    out_dir = os.path.abspath(a.out_dir or os.getcwd())
    os.makedirs(out_dir, exist_ok=True)
    print(f"[traceflow] tracing code under {', '.join(include)}", file=sys.stderr)
    if a.security and (a.no_io or a.no_values or a.no_library or a.builtins == "none"):
        print("[traceflow] note: --no-io/--no-values/--no-library/--builtins none hide data that security checks use",
              file=sys.stderr)

    tracer = Tracer(
        include=include,
        builtins=a.builtins,
        library_calls=not a.no_library,
        capture_values=not a.no_values,
        capture_io=not a.no_io,
    )
    # live mode always watches activity: intercept rules need it
    monitor = security.SecurityMonitor(tracer) if a.security or a.live else None
    meta = {"script": script or f"-m {module}", "module": a.module and module, "root": root,
            "argv": app_args, "python": platform.python_version(),
            "recorded_at": datetime.now().isoformat(timespec="seconds")}
    server = start_live(a, tracer, monitor, meta) if a.live else None
    sys.argv = [script or module, *app_args]
    sys.path.insert(0, entry_dir)
    exit_status, error = 0, None
    if monitor:
        monitor.start()
    tracer.start()
    try:
        if script:
            runpy.run_path(script, run_name="__main__")
        else:
            runpy.run_module(module, run_name="__main__", alter_sys=True)
    except SystemExit as e:
        exit_status = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except KeyboardInterrupt:
        exit_status, error = 130, "KeyboardInterrupt"
    except BaseException as e:  # noqa: BLE001 - we want to keep the trace whatever happened
        exit_status, error = 1, f"{type(e).__name__}: {e}"
        tb = traceback.format_exc()
    finally:
        if tracer.ctl:
            tracer.ctl.shutdown()  # release threads still paused, stop pausing
        if monitor:
            monitor.stop()
        tracer.stop()
    if error and error != "KeyboardInterrupt":
        sys.stderr.write(tb)

    meta.update(exit_status=exit_status, error=error)
    trace = store.trace_to_dict(tracer, meta)
    if monitor:
        trace["security"] = run_security_checks(trace, tracer, monitor, root, a)
    written = []
    if not a.no_json:
        p = os.path.join(out_dir, f"{base}.trace.json"); store.save_json(trace, p); written.append(p)
    if a.sqlite:
        p = os.path.join(out_dir, f"{base}.trace.db"); store.save_sqlite(trace, p); written.append(p)
    view = graph.build(trace)
    p = os.path.join(out_dir, f"{base}.trace.html"); render.write_html(view, p); written.append(p)
    if server:
        # hand the finished trace (findings, masking) to the open live viewer, then shut the server down
        view["meta"] = {**view["meta"], "saved_to": p}
        server.final = view
        if server.connected.is_set():
            server.final_sent.wait(10)
        server.stop()

    print(f"\n[traceflow] {len(tracer.calls)} calls recorded"
          f"{' (truncated)' if tracer.truncated else ''} in {tracer.t_end / 1e6:.1f} ms", file=sys.stderr)
    if monitor:
        sec = trace["security"]
        s, kinds = sec["summary"], {}
        for act in sec["activity"]:
            kinds[act["kind"]] = kinds.get(act["kind"], 0) + 1
        print(f"[traceflow] security: {s['high']} high, {s['medium']} medium, {s['low']} low"
              + (f" · activity: {', '.join(f'{n} {k}' for k, n in sorted(kinds.items()))}" if kinds else "")
              + (f" · {sec['redacted']} secret(s) masked in the trace" if sec["redacted"] else ""), file=sys.stderr)
    for p in written:
        print(f"[traceflow] wrote {p}", file=sys.stderr)
    if not a.no_open and not server:  # the live viewer is already open and now shows the final trace
        webbrowser.open(Path(written[-1]).as_uri())
    return exit_status


def start_live(a, tracer, monitor, meta):
    ctl = live.Controller(tracer)
    tracer.ctl = monitor.ctl = ctl
    if a.intercept:
        ctl.configure(intercepts=[k.strip() for k in a.intercept.split(",")])
    if a.pause_at_start:
        ctl.command("pause")
    server = live.LiveServer(tracer, ctl, monitor, meta)
    server.start()
    print(f"[traceflow] live viewer: {server.url}", file=sys.stderr)
    if not a.no_open:
        webbrowser.open(server.url)
    # don't start the program before the viewer is there, or a short script would be over already
    print("[traceflow] waiting for the viewer to connect…", file=sys.stderr)
    if not server.connected.wait(30 if not a.no_open else 300):
        print("[traceflow] no viewer connected; running anyway", file=sys.stderr)
    return server


def _which(name: str):
    """Find an executable on PATH, plus common install dirs that a GUI-launched
    process (VS Code, Finder) may be missing from its PATH, on any OS."""
    exe = shutil.which(name)
    if exe:
        return exe
    dirs = []
    if sys.platform == "win32":
        name += ".exe" if "." not in name else ""
        dirs = [os.path.expandvars(r"%ProgramFiles%\nodejs"), os.path.expandvars(r"%ProgramFiles(x86)%\nodejs"),
                os.path.expandvars(r"%APPDATA%\npm"), os.path.expanduser(r"~\scoop\shims")]
    else:  # macOS, Linux
        dirs = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin",
                os.path.expanduser("~/.volta/bin"), os.path.expanduser("~/.local/bin"), "/snap/bin"]
        # nvm installs under ~/.nvm/versions/node/<ver>/bin; pick the newest
        nvm = os.path.expanduser("~/.nvm/versions/node")
        if os.path.isdir(nvm):
            dirs += [os.path.join(nvm, v, "bin") for v in sorted(os.listdir(nvm), reverse=True)]
    for d in dirs:
        cand = os.path.join(d, name)
        if os.path.exists(cand):
            return cand
    return None


def find_node():
    return _which("node")


def _node_install_hint() -> str:
    if sys.platform == "win32":
        return "Install it from https://nodejs.org (or: winget install OpenJS.NodeJS.LTS), then try again."
    if sys.platform == "darwin":
        return "Install it from https://nodejs.org (or: brew install node), then try again."
    return "Install it from https://nodejs.org (or your package manager, e.g. apt install nodejs npm), then try again."


def cmd_run_node(a):
    node = find_node()
    if not node:
        sys.exit("traceflow: this looks like a JavaScript/TypeScript file, but Node.js wasn't found.\n"
                 + _node_install_hint())
    if a.live:
        print("[traceflow] note: --live isn't supported for JavaScript/TypeScript yet; "
              "recording a normal trace.", file=sys.stderr)
    script = os.path.abspath(a.script)
    entry_dir = os.path.dirname(script)
    base = os.path.splitext(os.path.basename(script))[0]
    root = os.path.abspath(a.root) if a.root else (os.path.abspath(a.include[0]) if a.include
                                                   else find_project_root(entry_dir, markers=("package.json", ".git")))
    out_dir = os.path.abspath(a.out_dir or os.getcwd())
    os.makedirs(out_dir, exist_ok=True)
    js_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "js")
    runner = os.path.join(js_dir, "run.mjs")
    if not os.path.isdir(os.path.join(js_dir, "node_modules", "acorn")):
        npm = _which("npm") or (_which("npm.cmd") if sys.platform == "win32" else None)
        if not npm:
            sys.exit("traceflow: the Node recorder needs 'acorn', and npm wasn't found to install it.\n"
                     f"Run this once: npm install --prefix \"{js_dir}\"")
        print("[traceflow] first run: installing the Node recorder's dependency (acorn)…", file=sys.stderr)
        if subprocess.run([npm, "install", "--prefix", js_dir, "--no-fund", "--no-audit"]).returncode != 0:
            sys.exit("traceflow: couldn't install acorn. Run manually: npm install --prefix \"" + js_dir + "\"")
    trace_json = os.path.join(out_dir, f"{base}.trace.json")
    meta = {"recorded_at": datetime.now().isoformat(timespec="seconds")}
    print(f"[traceflow] tracing JavaScript/TypeScript under {root} with {node}", file=sys.stderr)
    cmd = [node, "--disable-warning=ExperimentalWarning", runner,
           "--root", root, "--out", trace_json, "--meta", json.dumps(meta)]
    if a.security:
        cmd.append("--security")
    cmd += ["--", script, *a.args]
    try:
        ver = subprocess.run([node, "--version"], capture_output=True, text=True)
        major = int(ver.stdout.strip().lstrip("v").split(".")[0]) if ver.stdout.strip() else 0
        if major and major < 20:
            print(f"[traceflow] warning: Node {ver.stdout.strip()} is old; TypeScript and some features need "
                  "Node 22.6+ (24 LTS recommended).", file=sys.stderr)
    except (OSError, ValueError):
        pass
    try:
        proc = subprocess.run(cmd)
    except OSError as e:
        sys.exit(f"traceflow: couldn't run Node.js: {e}")
    if not os.path.exists(trace_json):
        sys.exit("traceflow: the program produced no trace (it may have failed to start).")
    trace = store.load_json(trace_json)
    if a.security:
        trace["security"] = run_node_security_checks(trace, root, a)
        trace.pop("security_raw", None)
        store.save_json(trace, trace_json)  # rewrite with findings + masked secrets
    written = [trace_json]
    if a.sqlite:
        p = os.path.join(out_dir, f"{base}.trace.db"); store.save_sqlite(trace, p); written.append(p)
    view = graph.build(trace)
    p = os.path.join(out_dir, f"{base}.trace.html"); render.write_html(view, p); written.append(p)
    print(f"\n[traceflow] {len(trace['calls'])} calls recorded"
          f"{' (truncated)' if trace['meta'].get('truncated') else ''} in {trace['meta']['duration_ns'] / 1e6:.1f} ms",
          file=sys.stderr)
    if a.security:
        sec = trace["security"]
        s, kinds = sec["summary"], {}
        for act in sec["activity"]:
            kinds[act["kind"]] = kinds.get(act["kind"], 0) + 1
        print(f"[traceflow] security: {s['high']} high, {s['medium']} medium, {s['low']} low"
              + (f" · activity: {', '.join(f'{n} {k}' for k, n in sorted(kinds.items()))}" if kinds else "")
              + (f" · {sec['redacted']} secret(s) masked in the trace" if sec["redacted"] else ""), file=sys.stderr)
    for p in written:
        print(f"[traceflow] wrote {p}", file=sys.stderr)
    if not a.no_open:
        webbrowser.open(Path(written[-1]).as_uri())
    return proc.returncode


def run_node_security_checks(trace, root, a) -> dict:
    raw = trace.get("security_raw") or {"activity": [], "env_secrets": {}, "findings": [], "packages": []}
    packages = raw.get("packages") or []
    note = None
    if not packages:
        note = "No third-party packages were loaded, so there was nothing to check for known vulnerabilities."
    elif a.offline:
        note = f"{len(packages)} npm package(s) loaded; not checked for known vulnerabilities (--offline)."
    else:
        print(f"[traceflow] checking {len(packages)} loaded npm package(s) against OSV.dev", file=sys.stderr)
        try:
            osv.check(packages, ecosystem="npm")
            note = f"{len(packages)} loaded npm package(s) checked against OSV.dev."
        except Exception as e:  # noqa: BLE001
            note = f"Couldn't reach OSV.dev to check {len(packages)} npm package(s): {e}"
    return security.build_report(trace, raw.get("activity") or [], raw.get("env_secrets") or {}, root,
                                 packages, note, lang="javascript", extra_findings=raw.get("findings") or [],
                                 redact=not a.no_redact)


def run_security_checks(trace, tracer, monitor, root, a) -> dict:
    packages, note = [], None
    try:
        packages = osv.imported_distributions(c["module"] for c in tracer.calls if c["kind"] == "library")
    except Exception as e:  # noqa: BLE001 - a broken install shouldn't lose the trace
        note = f"Couldn't list installed packages: {e}"
    if not packages:
        note = note or "No third-party packages were imported, so there was nothing to check for known vulnerabilities."
    elif a.offline or not a.security:
        why = "--offline" if a.offline else "add --security to look them up on OSV.dev"
        note = f"{len(packages)} third-party package(s) imported; not checked for known vulnerabilities ({why})."
    else:
        print(f"[traceflow] checking {len(packages)} imported package(s) against OSV.dev", file=sys.stderr)
        try:
            osv.check(packages)
            note = f"{len(packages)} imported third-party package(s) checked against OSV.dev."
        except Exception as e:  # noqa: BLE001 - offline, proxy, API change...
            note = f"Couldn't reach OSV.dev to check {len(packages)} package(s) for known vulnerabilities: {e}"
    return security.build_report(trace, monitor.activity, monitor.env_secrets, root, packages, note,
                                  lang="python", truncated=monitor.truncated, redact=not a.no_redact)


def cmd_render(a):
    trace = store.load_json(a.trace)
    out = a.output or a.trace.replace(".json", "") + ".html"
    render.write_html(graph.build(trace), out)
    print(f"[traceflow] wrote {out}", file=sys.stderr)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="traceflow", description="Python runtime execution visualizer")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run and trace a Python script or module")
    r.add_argument("script", nargs="?")
    r.add_argument("args", nargs=argparse.REMAINDER, help="arguments passed to the script")
    r.add_argument("-m", dest="module", nargs=argparse.REMAINDER, metavar="MODULE [ARGS]",
                   help="run a module like `python -m` (must come last; everything after it goes to the module)")
    r.add_argument("-o", "--out-dir", help="where to write trace files (default: cwd)")
    r.add_argument("--root", help="project root to trace (default: nearest folder with pyproject.toml/setup.py/"
                                  "setup.cfg/.git, else the cwd if the entry point is inside it)")
    r.add_argument("-I", "--include", action="append", help="directory to trace (repeatable; overrides --root)")
    r.add_argument("--builtins", choices=["none", "module", "all"], default="module",
                   help="C calls to record: module-level functions like print/input (default), all incl. methods, or none")
    r.add_argument("--no-library", action="store_true", help="don't record calls into stdlib/site-packages")
    r.add_argument("--no-values", action="store_true", help="don't capture argument/return reprs")
    r.add_argument("--no-io", action="store_true", help="don't capture stdout/stderr/stdin")
    r.add_argument("--sqlite", action="store_true", help="also write a SQLite event store")
    r.add_argument("--no-json", action="store_true", help="skip the JSON event store")
    r.add_argument("--no-open", action="store_true", help="don't open the viewer in a browser afterwards")
    r.add_argument("--security", action="store_true",
                   help="record files, processes, network, SQL and eval/exec, and report security findings (OWASP Top 10)")
    r.add_argument("--offline", action="store_true", help="with --security: don't look up imported packages on OSV.dev")
    r.add_argument("--no-redact", action="store_true", help="with --security: keep detected secrets unmasked in the trace")
    r.add_argument("--live", action="store_true",
                   help="watch the program in the browser as it runs: pause, step, breakpoints, intercept and edit")
    r.add_argument("--pause-at-start", action="store_true", help="with --live: pause before the first line runs")
    r.add_argument("--intercept", metavar="RULES",
                   help="with --live: comma-separated intercept rules to start with: " + ", ".join(live.INTERCEPTS))
    r.add_argument("--lang", choices=["auto", "python", "py", "js", "node"], default="auto",
                   help="which recorder to use (default: auto, by file extension)")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("render", help="render a saved .trace.json to HTML")
    s.add_argument("trace")
    s.add_argument("-o", "--output")
    s.set_defaults(func=cmd_render)

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
