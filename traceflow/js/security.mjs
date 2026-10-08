// JavaScript/TypeScript security monitor. Patches Node's built-in modules before
// the program runs so each sensitive operation (file, process, network, dynamic
// code, weak crypto, TLS-off) is recorded as an activity entry or a finding, in the
// same shape traceflow's Python engine already analyses. Attribution is to the user
// function running at the time (the top of the recorder's call stack).

import { createRequire } from "node:module";
import { URL } from "node:url";

const require = createRequire(import.meta.url);

const SENSITIVE = [
  [/[\\/]\.ssh[\\/]/i, "an SSH key or config"],
  [/[\\/]\.aws[\\/](credentials|config)$|[\\/]\.azure[\\/]|[\\/]\.kube[\\/]config$|[\\/]\.docker[\\/]config\.json$/i, "cloud credentials"],
  [/[\\/]\.env(\.[^\\/]*)?$/i, "an environment secrets file"],
  [/[\\/]\.git-credentials$|[\\/][._]netrc$|[\\/]\.npmrc$|[\\/]\.pgpass$/i, "stored credentials"],
  [/\.(pem|key|pfx|p12|jks|keystore)$|[\\/]id_(rsa|dsa|ecdsa|ed25519)[^\\/]*$/i, "a private key or certificate"],
  [/^\/etc\/(passwd|shadow|sudoers)$/i, "the system account database"],
  [/[\\/]microsoft[\\/](credentials|protect|vault)[\\/]/i, "the Windows credential store"],
];
const ENV_SECRET = /key|token|secret|pass|pwd|credential|auth|private/i;

export function sensitiveLabel(p) {
  const s = String(p);
  for (const [rx, label] of SENSITIVE) if (rx.test(s)) return label;
  return null;
}

function envSecrets() {
  const out = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (ENV_SECRET.test(k) && v && v.length >= 8 && !/\s/.test(v) && !v.includes(";") && !/^([A-Za-z]:)?[\\/]/.test(v))
      out[v] = `value of $${k}`;
  }
  return out;
}

export class SecurityMonitor {
  constructor(rt) {
    this.rt = rt;
    this.active = false;
    this.envSecrets = {};
    this.findings = [];
    this._seen = new Set();
    this._depth = 0; // guard against our own wrapped calls re-entering
  }

  start() {
    this.envSecrets = envSecrets();
    this._patchFs();
    this._patchChildProcess();
    this._patchNet();
    this._patchHttp();
    this._patchCrypto();
    this._patchVm();
    this._patchEval();
    this.active = true;
  }

  stop() {
    this.active = false;
    Object.assign(this.envSecrets, envSecrets()); // picks up anything the program loaded (e.g. from .env)
  }

  // location of the user function running now
  _loc() {
    const stack = this.rt.stack;
    for (let i = stack.length - 1; i >= 0; i--) {
      const id = stack[i];
      if (id != null) { const c = this.rt.calls[id]; return { call: id, file: c.file, line: c.def_line }; }
    }
    return { call: null, file: null, line: null };
  }

  record(entry) {
    if (!this.active || this._depth > 0) return;
    const loc = this._loc();
    const e = { seq: this.rt.events.length, t: this.rt.nowNs(), sensitive: false, ...entry, ...loc };
    if (e.path) e.sensitive = !!sensitiveLabel(e.path);
    (this.rt.activity ||= []).push(e);
  }

  finding(f) {
    const key = f.rule + "|" + (f.dedupe ?? JSON.stringify([f.call, f.file, f.line, f.evidence]));
    if (this._seen.has(key)) return;
    this._seen.add(key);
    const loc = f.call !== undefined ? {} : this._loc();
    this.findings.push({ owasp: null, ...f, ...loc, call: f.call ?? loc.call });
  }

  _wrap(obj, name, make) {
    const orig = obj[name];
    if (typeof orig !== "function") return;
    const mon = this;
    obj[name] = function (...args) {
      try { if (mon.active && mon._depth === 0) make(args); } catch {}
      mon._depth++;
      try { return orig.apply(this, args); } finally { mon._depth--; }
    };
  }

  _patchFs() {
    for (const modName of ["node:fs", "node:fs/promises"]) {
      let m;
      try { m = require(modName); } catch { continue; }
      const reads = ["readFile", "readFileSync", "createReadStream", "open", "openSync"];
      const writes = ["writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream"];
      const dels = ["unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync"];
      for (const fn of reads) this._wrap(m, fn, (a) => this._file(a[0], fn, "read", false));
      for (const fn of writes) this._wrap(m, fn, (a) => this._file(a[0], fn, "write", true));
      for (const fn of dels) this._wrap(m, fn, (a) => this._file(a[0], fn, "delete", true));
      this._wrap(m, "rename", (a) => this._file(a[1], "rename", "rename", true));
      this._wrap(m, "renameSync", (a) => this._file(a[1], "rename", "rename", true));
    }
  }

  _file(p, fn, op, write) {
    if (typeof p !== "string" && !(p && p.toString)) return;
    let path = typeof p === "string" ? p : (p instanceof URL ? p.pathname : String(p));
    if (/^\d+$/.test(path)) return; // fd
    if (/^\/[A-Za-z]:[\\/]/.test(path)) path = path.slice(1).replace(/\//g, "\\"); // /D:/x -> D:\x (file-URL form)
    // skip the module loader reading source files (the program's own code, deps): not program behaviour
    if (op === "read" && this.isLoaderRead && this.isLoaderRead(path)) return;
    this.record({ kind: op === "delete" ? "delete" : "file", op, target: path, path, write });
  }

  _patchChildProcess() {
    let m;
    try { m = require("node:child_process"); } catch { return; }
    const shellCmds = ["exec", "execSync"];
    const fileCmds = ["execFile", "execFileSync", "spawn", "spawnSync", "fork"];
    for (const fn of shellCmds) this._wrap(m, fn, (a) => {
      this.record({ kind: "process", op: "shell", target: String(a[0] ?? "") });
    });
    for (const fn of fileCmds) this._wrap(m, fn, (a) => {
      const file = String(a[0] ?? "");
      const args = Array.isArray(a[1]) ? a[1].map(String) : [];
      const opts = (Array.isArray(a[1]) ? a[2] : a[1]) || {};
      const shell = opts && opts.shell;
      this.record({ kind: "process", op: shell ? "shell" : "run", target: [file, ...args].join(" ") });
    });
  }

  _patchNet() {
    let m;
    try { m = require("node:net"); } catch { return; }
    this._wrap(m, "connect", (a) => this._conn(a));
    this._wrap(m, "createConnection", (a) => this._conn(a));
  }
  _conn(a) {
    const o = a[0];
    let host = null, port = null;
    if (o && typeof o === "object") { host = o.host || o.path; port = o.port; }
    else { port = o; host = a[1]; }
    if (host) this.record({ kind: "network", op: "connect", target: port ? `${host}:${port}` : String(host), host: String(host), port });
  }

  _patchHttp() {
    for (const modName of ["node:http", "node:https"]) {
      let m;
      try { m = require(modName); } catch { continue; }
      const scheme = modName.endsWith("https") ? "https" : "http";
      for (const fn of ["request", "get"]) this._wrap(m, fn, (a) => this._req(a, scheme));
    }
  }
  _req(a, scheme) {
    let url = null, method = "GET", opts = null;
    if (typeof a[0] === "string") { url = a[0]; opts = a[1]; }
    else if (a[0] instanceof URL) { url = a[0].href; opts = a[1]; }
    else if (a[0] && typeof a[0] === "object") {
      opts = a[0];
      const host = opts.hostname || opts.host || "localhost";
      const path = opts.path || "/";
      url = `${opts.protocol || scheme + ":"}//${host}${opts.port ? ":" + opts.port : ""}${path}`;
      method = opts.method || "GET";
    }
    if (typeof a[1] === "object" && a[1]) method = a[1].method || method;
    let host = null;
    try { host = new URL(url).hostname; } catch {}
    this.record({ kind: "network", op: method, target: url || "(request)", url, host });
    // TLS verification disabled?
    const checkOpts = (opts && typeof opts === "object") ? opts : null;
    if (scheme === "https" && checkOpts && checkOpts.rejectUnauthorized === false) {
      this.finding({ rule: "config.tls_disabled", owasp: "A02", severity: "high",
        title: "TLS certificate checking turned off",
        detail: "A request set rejectUnauthorized: false. Anyone on the network can impersonate the server and read or change the traffic.",
        fix: "Remove rejectUnauthorized: false. For internal CAs, pass the ca option instead.", evidence: url });
    }
  }

  _patchCrypto() {
    let m;
    try { m = require("node:crypto"); } catch { return; }
    const self = this;
    for (const fn of ["createHash", "createHmac"]) {
      const orig = m[fn];
      if (typeof orig !== "function") continue;
      m[fn] = function (algo, ...rest) {
        try {
          if (self.active && self._depth === 0 && /^(md5|sha1)$/i.test(String(algo))) {
            self.finding({ rule: "crypto.weak_hash", owasp: "A04", severity: "low",
              title: `Weak hash algorithm (${String(algo).toUpperCase()})`,
              detail: `${String(algo).toUpperCase()} is broken for security use: collisions are cheap and it is far too fast for passwords.`,
              fix: "Passwords: scrypt, argon2 or bcrypt. Integrity checks: sha256.", dedupe: String(algo).toLowerCase() });
          }
        } catch {}
        return orig.call(this, algo, ...rest);
      };
    }
  }

  _patchVm() {
    let m;
    try { m = require("node:vm"); } catch { return; }
    for (const fn of ["runInThisContext", "runInNewContext", "runInContext", "compileFunction"])
      this._wrap(m, fn, (a) => this.record({ kind: "code", op: "vm", target: String(a[0] ?? "").slice(0, 2000) }));
  }

  _patchEval() {
    // eval can't be wrapped (it's a keyword), but Function() can
    const self = this;
    const OrigFunction = globalThis.Function;
    function TracedFunction(...args) {
      try {
        if (self.active && self._depth === 0 && args.length)
          self.record({ kind: "code", op: "eval", target: String(args[args.length - 1] ?? "").slice(0, 2000) });
      } catch {}
      return OrigFunction.apply(this, args);
    }
    TracedFunction.prototype = OrigFunction.prototype;
    try { globalThis.Function = TracedFunction; } catch {}
  }

  recordEval(code) {
    this.record({ kind: "code", op: "eval", target: String(code ?? "").slice(0, 2000) });
  }

  report() {
    return { activity: this.rt.activity || [], env_secrets: this.envSecrets, findings: this.findings };
  }
}
