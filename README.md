# Traceflow — runtime execution visualizer

Run a Python or JavaScript/TypeScript program under observation, record everything
that happened, and reconstruct the execution path as an interactive graph. The
pipeline below is the Python engine; a Node.js recorder (see
[JavaScript and TypeScript](#javascript-and-typescript)) feeds the same viewer.

```
Target Python program
        ↓
Runtime tracing engine   traceflow/tracer.py   sys.settrace + sys.setprofile
        ↓
Execution event store    traceflow/store.py    JSON (default) and SQLite (--sqlite)
        ↓
Graph builder            traceflow/graph.py    call tree, function graph, branch analysis
        ↓
Diagram renderer         traceflow/render.py + viewer.html   one self-contained HTML file
```

Runs on Windows, macOS and Linux. No dependencies beyond the standard library.
Python 3.10+ (3.11+ gives qualified names like `Application.authenticate`).
Tracing JavaScript/TypeScript additionally needs Node.js (see that section).

## Install

Install once, so the `traceflow` command works from any project folder:

```bash
pip install -e /path/to/Traceflow      # editable: changes to this repo take effect immediately
# Windows:  pip install -e D:\Traceflow
```

Install it into the same Python (or virtualenv) the project you're tracing uses, so its
dependencies import normally. Use `python3`/`pip3` on systems where `python` is Python 2.

## Usage

```bash
# traceflow options go BEFORE the script; everything after the script goes to the script
traceflow run [options] your_app.py [your app's args]
traceflow run [options] -m your_package [your app's args]   # like `python -m your_package`

traceflow run -o traces --sqlite examples/app.py
echo 1 | traceflow run examples/scanner_app.py     # feed input() non-interactively

traceflow render traces/app.trace.json -o app.html  # re-render a saved trace
```

`python -m traceflow ...` works too, from this folder or after installing.

### Tracing a whole project

Run it from the project's root folder, the same way you'd start the project:

```bash
cd path/to/project
traceflow run -m myapp            # project started with `python -m myapp`
traceflow run src/myapp/main.py   # project started with `python src/myapp/main.py`
```

Every file in the project is traced, across all folders. The project root is the
nearest folder (at or above the entry point) containing `pyproject.toml`, `setup.py`,
`setup.cfg` or `.git`; failing that, the current folder if the entry point is inside
it. The first line of output says which folder is being traced; use `--root DIR` to
change it. Installed packages and the standard library are never traced inside, even
when a virtualenv lives in the project folder.

`examples/shop/` is a small multi-package project to try it on:

```bash
cd examples/shop
traceflow run -m shop save10
```

The `.trace.html` viewer opens in your browser when the run ends (`--no-open` to skip). Interactive programs work normally:
answer the prompts in your terminal, or press Ctrl+C. The trace is saved either way.

| Option | Effect |
|---|---|
| `-o DIR` | Output directory (default: current directory) |
| `-m MODULE` | Run a module like `python -m MODULE`. Must come last: everything after it goes to the module |
| `--root DIR` | Project root to trace. Default: detected (see above) |
| `-I DIR` | Directory to trace (repeatable). Overrides `--root` |
| `--builtins module\|all\|none` | C calls to record. `module` = print, input, time.sleep, open… (default); `all` adds C methods like `list.append` |
| `--no-library` | Don't record calls into stdlib / site-packages |
| `--no-values` | Don't capture argument and return value reprs |
| `--no-io` | Don't capture stdout/stderr/stdin |
| `--sqlite` | Also write a SQLite event store |
| `--no-open` | Don't open the viewer in a browser afterwards |
| `--security` | Security mode (see below) |
| `--offline` | With `--security`: don't look up imported packages on OSV.dev |
| `--no-redact` | With `--security`: keep detected secrets unmasked in the trace files |
| `--live` | Watch the program in the browser while it runs (see below) |
| `--pause-at-start` | With `--live`: pause before the first line, so you can set breakpoints first |
| `--intercept RULES` | With `--live`: start with these intercept rules on, e.g. `process,network` |

## Live mode

```bash
traceflow run --live your_app.py
traceflow run --live --pause-at-start --intercept process,network,sensitive your_app.py
```

The viewer opens right away and fills in as the program runs. The program waits
(up to 30 s) for the viewer to connect before it starts. When it finishes, the
page switches to the complete trace, with findings and masked secrets, and the
usual files are saved.

**Pause and step**: **Pause** stops at the next line of your code. While paused,
**Continue** runs to the next breakpoint or intercept, **Step into** goes to the
next line (entering calls), **Step over** to the next line in this function, and
**Step out** until the function returns. Time spent paused is left out of the
timings.

**Breakpoints**: in the inspector, **Break on call** pauses every time that
function is called, before its first line runs. Click a line number in the source
view to pause when that line is about to run. This works for library functions too,
e.g. to pause on `urlopen(url)`.

**Intercept** (like Burp's): pick rules in the toolbar (processes started, network
requests, file writes, file deletes, sensitive files, SQL queries, `eval`/`exec`).
The program stops just *before* doing it, and the inspector shows what it's about
to do, where, and the local variables. **Forward** lets it happen; **Drop** blocks
it: the program gets a `PermissionError`, as if the OS had refused. The Activity tab
marks each one forwarded or dropped.

**Edit values**: when paused on a function call (a call breakpoint or Step into),
its arguments are editable. Type Python literals (`'alice'`, `42`, `[1, 2]`,
`{'k': 1}`, `True`, `None`) and continue; the function runs with your values, and
the trace records what you changed. Values shown with `…` were too long to show in
full and can't be edited.

How it works and what to know:

- A small web server on `127.0.0.1` (never reachable from other machines) serves
  the viewer. The link in the terminal has a secret token; requests without it,
  for another hostname, or not sent as JSON are refused, so other websites open in
  your browser can't control the program.
- Pausing happens inside the tracer's callbacks, so other threads that reach
  your code wait too. A thread blocked in `input()`, `sleep()` or native code
  pauses when it gets back to Python.
- Edits use `frame.f_locals`, which CPython writes back to the function when the
  tracer callback returns.
- While running, the viewer shows raw values: masking happens when the program
  ends. The terminal stays interactive for `input()` prompts.
- Ctrl+C in the terminal stops the program, even while it's paused. Like any
  debugger, `--live` can't run under VS Code's debugger (F5).

## Security mode

```bash
traceflow run --security your_app.py
traceflow run --security examples/insecure/app.py   # Python demo; answers in inputs.txt
traceflow run --security examples/js-insecure/app.js "bad-host; whoami" "2+2"   # JS demo
```

Works for Python and JavaScript/TypeScript (see the JS section for what differs).
On top of the normal trace, security mode records **what the program did** and
reports **findings** mapped to the OWASP Top 10:2025. The viewer gets two extra tabs
next to Program output, a red/amber badge on every call with a finding, and a
Security section in the inspector. Click a finding to jump to the call.

**Activity** (Python audit hooks, PEP 578, plus a small sqlite3 wrapper), each entry
attached to the call that caused it, even when it happened deep inside a library:
files opened / written / deleted (credential files such as `.env`, `.ssh/`,
`.aws/credentials`, browser password stores are flagged), processes started,
outbound network connections and URLs, SQL statements, `eval`/`exec` of strings,
native libraries loaded, and classes loaded by pickle.

**Findings**

| What | OWASP 2025 | How it's detected |
|---|---|---|
| Secrets printed, logged, put in URLs or command lines | A09, A04 | Known key formats (AWS, GitHub, Slack, Stripe, Google, Anthropic, OpenAI, private keys, JWTs), `password=…` style values, and the values of secret-named environment variables |
| Hard-coded secrets | A07 | Same patterns, in source code that ran |
| SQL / command / code injection, XSS | A05 | Text the user typed (stdin, argv) appearing in SQL without parameters, a command, `eval`/`exec`, or unescaped HTML |
| Path traversal, SSRF | A01 | User input choosing a file path or network destination |
| Vulnerable packages | A03 | Third-party packages **imported during the run**, checked on OSV.dev; marked as called directly or only imported |
| Weak hashing, predictable randomness, plain HTTP | A04 | MD5/SHA-1 calls, `random` used in token/password functions, `http://` to non-local hosts |
| TLS checks off, debug mode | A02 | `verify=False`, `ssl._create_unverified_context`, `debug=True` |
| Unsafe deserialization | A08 | `pickle`, `marshal`, `yaml.load` without a safe loader |
| Fail-open / swallowed errors | A10 | An exception that **actually happened** and was caught by a handler that returns `True` or ignores it |

**Secrets are masked** in the saved trace (JSON, SQLite and HTML), including the
values of secret-named environment variables wherever they were captured. Trace
files still contain arguments and output, so treat them as sensitive.

**What it can't tell you**

- Only code that ran is checked. Branches the run didn't take have no findings.
- Taint tracking is by value: it spots input that reaches a sink unchanged or as a
  substring, not input that was transformed first. Inputs shorter than 3
  characters are ignored to avoid noise.
- Broken access control and insecure design (A01/A06 beyond the above) depend on
  your business rules and can't be detected automatically.
- Audit hooks observe well-behaved code. Native extensions can bypass them, and
  child processes aren't traced. **This is not a sandbox**: run untrusted code in a
  VM or container.
- `--security` sends the names and versions of imported third-party packages to
  api.osv.dev (nothing else). Use `--offline` to skip it.

Findings, activity and packages are also in the SQLite store (`findings`,
`activity`, `packages` tables).

## JavaScript and TypeScript

traceflow also traces Node.js programs. Point it at a `.js`, `.mjs`, `.cjs`, `.ts`,
`.mts` or `.cts` file and it uses the Node recorder automatically:

```bash
traceflow run app.ts
traceflow run server.js --port 3000     # args after the script go to your program
traceflow run --lang node app.js         # force the Node recorder
```

Requirements: **Node.js 22.6+** (for built-in TypeScript stripping; 24 LTS
recommended) — Windows `winget install OpenJS.NodeJS.LTS`, macOS `brew install node`,
Linux your package manager or https://nodejs.org. traceflow finds Node even when it's
installed via Homebrew, nvm, Volta or scoop and isn't on a GUI app's PATH. The first
JS/TS run installs one small dependency (`acorn`) into `traceflow/js/`. TypeScript
runs directly, with no separate compile step, and the viewer shows your original
`.ts` source.

The same viewer shows everything it does for Python: the call tree, the call graph,
per-call timing, arguments and return values, exceptions (a `throw` shows as raised,
a `catch` as caught), and captured `console.log` output tied to the call that wrote
it. Arrow functions, methods, and `async`/`await` are all recorded.

**Security mode works for JavaScript/TypeScript too** — `traceflow run --security app.ts`.
The Node recorder wraps the built-in `fs`, `child_process`, `net`, `http`/`https`,
`crypto` and `vm` modules (and `eval`/`Function`) to record the same activity and
findings: file/process/network/eval activity, hard-coded and printed secrets,
command/code injection and XSS from `process.argv`, SSRF, path traversal, secrets in
URLs, cleartext HTTP, weak hashing (`createHash('md5'|'sha1')`), TLS turned off
(`rejectUnauthorized: false`), and vulnerable npm packages (the ones loaded during
the run, checked on OSV.dev). Secrets are masked the same way.

Differences from Python security: taint sources are `process.argv` and stdin (not
HTTP request bodies); SQL injection isn't detected yet (no standard DB hook); the
fail-open/swallowed-error (A10) and predictable-randomness checks are Python-only so
far; and activity is seen only for calls made through Node's own modules (a native
addon doing its own I/O is missed). Detection covers code that ran during the trace.

What's Python-only for now: per-line execution and branch highlighting, live mode
(`--live`), and the A10/weak-random checks above. For concurrent `async` code,
parent/child nesting is approximate, because the recorder follows the call stack and
`await` unwinds it. These are the next things to add on the JS side.

## What the viewer shows when you click a call

- **Called by**: parent call, plus the exact file:line of the call site
- **Defined at**: file and line of the function
- **Duration**: total, self (excluding callees), and start offset
- **Arguments / return value** (truncated reprs)
- **Calls made**: every callee in order, with the line each was called from
- **Outcome**: returned, raised (type, message, line, where it propagated), or
  exceptions raised inside and caught here
- **Branches taken**: every `if/elif/else`, loop, `try/except` and `match` in the
  function with what actually happened (`True`, `False → else`, `3 iterations`,
  `handler ran: except ValueError`, `not reached`)
- **Source**: executed lines highlighted with hit counts, lines that didn't run dimmed

Program output is attributed to the call that wrote it, so clicking
"Initializing application" jumps to `authenticate → print`.

**Layout**: drag the gaps between panels to resize them (or focus a gap and use the
arrow keys; Shift for bigger steps). Double-click a gap to reset it. The – button on
a panel minimizes it; click its header or + to bring it back. Sizes are remembered
for the next trace you open in the same browser.

## How it works

**`sys.settrace`** fires `call`, `line`, `return` and `exception` events for every
Python frame. traceflow returns a per-frame local tracer only for user code, so stdlib
internals cost almost nothing. Line events give per-call line hit counts.

- *Raised vs returned*: an `exception` event followed by `return` (no `line` in
  between) means the exception propagated out. An `exception` followed by a `line`
  event means it was caught in that frame.
- *Branches*: the graph builder parses each function with `ast`, finds decision
  points, and compares them with that call's line hits. If `if x:` ran and the
  first line of its body ran, the True branch was taken.

**`sys.setprofile`** adds `c_call`/`c_return`/`c_exception`, which settrace never
sees. That's how `print()` and `input()` appear as nodes.

**Library boundary**: when user code calls into the stdlib (e.g. `json.dumps`),
that call is recorded as one opaque `library` node. Its internals are not traced.

**I/O capture**: stdout, stderr and stdin are wrapped so every write and read is
tagged with the call on top of the stack at that moment.

## Event store format

`*.trace.json` contains `meta`, `calls` (one record per invocation: parent,
children, timing, status, args, return, exception, line hits, line arcs),
`events` (ordered: call, return, raise, catch, stdout, stderr, stdin) and
`sources`. The SQLite store has the same data in tables `calls`, `events`,
`line_hits`, `arcs`, `sources`, `meta`, so you can query it directly:

```sql
SELECT qualname, (end_ns - start_ns)/1e6 AS ms FROM calls ORDER BY ms DESC LIMIT 10;
SELECT * FROM calls WHERE status = 'raised';
```

## Known limitations

- **Overhead**: line tracing slows pure-Python code a lot (often 5–20×), so
  absolute timings are inflated. Relative timings are still useful.
- **Generators/coroutines**: each resume is its own call record, marked
  `suspended`. settrace can't cheaply tell a `yield` from a final `return`.
- **`input()` prompt**: because stdout is wrapped, `input()` uses its plain
  fallback (no readline line-editing). Use `--no-io` if you need it.
- **Builtin return values** aren't exposed to profile hooks, so they show as
  unknown (stdin capture still records what the user typed).
- **Threads** are traced, but the viewer doesn't separate them into lanes yet.
- **C extensions** calling back into Python: callbacks attach to the nearest traced
  parent.

## Next steps

- **JavaScript parity**: per-line coverage and branch highlighting, plus
  `--security` and `--live` for the Node recorder.
- **OS-level security monitoring** (ETW on Windows, eBPF/strace on Linux,
  Endpoint Security on macOS): catches files, processes and network in any
  language, and for untrusted code that bypasses in-language hooks.
- **`sys.monitoring` backend** (PEP 669, Python 3.12+): per-code-object event
  enabling and `BRANCH` events, with much lower overhead than settrace. It's the
  natural replacement for `tracer.py` on modern Python.
- **Attach to a running process** (`sys.remote_exec` on 3.14+).
- **Optional Claude layer**: send a call's record, branches and source to the
  Claude API to explain why the program took the path it did.
